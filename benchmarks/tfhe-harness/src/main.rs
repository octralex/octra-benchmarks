#![recursion_limit = "256"]

mod wide;

use std::io::{self, Write};
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as PARAMETERS;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16, FheUint64};

fn write_rusage(output: &str) -> Result<(), String> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if result != 0 || usage.ru_maxrss <= 0 {
        return Err("getrusage failed".into());
    }
    let (multiplier, raw_unit, unit) = if cfg!(target_os = "macos") {
        (1_u64, "bytes", "bytes (macOS getrusage RUSAGE_SELF)")
    } else if cfg!(target_os = "linux") {
        (1024_u64, "KiB", "bytes (Linux getrusage RUSAGE_SELF, ru_maxrss KiB converted to bytes)")
    } else {
        return Err("unsupported getrusage platform".into());
    };
    let raw = usage.ru_maxrss as u64;
    let bytes = raw.checked_mul(multiplier).ok_or("getrusage overflow")?;
    let document = serde_json::json!({
        "process_peak_rss_bytes": bytes,
        "process_peak_rss_raw": raw,
        "process_peak_rss_raw_unit": raw_unit,
        "process_peak_rss_unit": unit,
        "process_peak_rss_source": "adapter_exit",
        "scope": "whole process including setup, validation and serialization, not eval-only allocation"
    });
    std::fs::write(format!("{output}.rusage.json"), format!("{document}\n")).map_err(|e| e.to_string())
}

#[derive(Default)]
struct Args {
    case: String,
    output: String,
    key_output: String,
    repetitions: usize,
    warmups: usize,
    threads: usize,
    width: u8,
    batch: usize,
    fixture_count: usize,
    selftest: bool,
    wide: bool,
    build_info: bool,
}

fn args() -> Result<Args, String> {
    let mut a = Args { case: "S-add".into(), repetitions: 1, warmups: 1, threads: 1, width: 16, batch: 1, fixture_count: 1, ..Default::default() };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut value = || it.next().ok_or_else(|| "missing argument".to_string());
        match k.as_str() {
            "--case" => a.case = value()?,
            "--output" => a.output = value()?,
            "--key-output" => a.key_output = value()?,
            "--repetitions" => a.repetitions = value()?.parse().map_err(|_| "bad repetitions")?,
            "--warmups" => a.warmups = value()?.parse().map_err(|_| "bad warmups")?,
            "--threads" => a.threads = value()?.parse().map_err(|_| "bad threads")?,
            "--width" => a.width = value()?.parse().map_err(|_| "bad width")?,
            "--batch" => a.batch = value()?.parse().map_err(|_| "bad batch")?,
            "--fixture-count" => a.fixture_count = value()?.parse().map_err(|_| "bad fixture count")?,
            "--selftest" => a.selftest = true,
            "--wide" => a.wide = true,
            "--build-info" => a.build_info = true,
            _ => return Err(format!("unknown argument: {k}")),
        }
    }
    if a.build_info { return Ok(a); }
    if a.output.is_empty() || a.repetitions == 0 || a.fixture_count == 0 || ![1, 4].contains(&a.threads) ||
        (a.batch != 1 && !(a.wide && matches!(a.case.as_str(), "I63-add" | "F127-add"))) {
        return Err("invalid arguments, micro-batching is admitted only for wide addition cases".into());
    }
    Ok(a)
}

fn inputs() -> Result<(Vec<u64>, Vec<u64>), String> {
    let mut x = String::new();
    let mut y = String::new();
    if io::stdin().read_line(&mut x).map_err(|e| e.to_string())? == 0 {
        return Err("missing input vector".into());
    }
    io::stdin().read_line(&mut y).map_err(|e| e.to_string())?;
    let parse = |line: &str| -> Result<Vec<u64>, String> {
        if line.trim().is_empty() { return Ok(Vec::new()); }
        line.split(',')
            .map(|s| s.trim().parse::<u64>().map_err(|_| "empty or invalid input token".to_string()))
            .collect()
    };
    Ok((parse(&x)?, parse(&y)?))
}

fn depth(case: &str) -> usize {
    case[2..].parse().unwrap_or(0)
}

fn check_shape(a: &Args, x: &[u64], y: &[u64]) -> Result<(), String> {
    let n = if a.case == "V64" || a.case == "D64" { 64 } else { 1 };
    if x.len() != n { return Err("wrong x shape".into()); }
    if matches!(a.case.as_str(), "S-add" | "S-mul" | "V64" | "D64") || a.case.starts_with("CH") {
        if y.len() != n { return Err("wrong y shape".into()); }
    }
    if !matches!(a.case.as_str(), "S-add" | "S-mul" | "V64" | "D64" | "P3" | "CH1" | "CH2" | "CH4" | "SQ1" | "SQ2" | "SQ3") {
        return Err("unknown case".into());
    }
    Ok(())
}

macro_rules! execute {
    ($a:expr, $x:expr, $y:expr, $ct:ty, $clear:ty) => {{
        let pool = rayon::ThreadPoolBuilder::new().num_threads($a.threads).build().map_err(|e| e.to_string())?;
        let setup_start = Instant::now();
        let config = ConfigBuilder::default().use_custom_parameters(PARAMETERS).build();
        let (client_key, server_key) = pool.install(|| generate_keys(config));
        let keygen_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
        set_server_key(server_key.clone());
        let broadcast_start = Instant::now();
        pool.broadcast(|_| set_server_key(server_key.clone()));
        let key_install_ms = broadcast_start.elapsed().as_secs_f64() * 1000.0;
        let parameter_json = serde_json::to_string(&PARAMETERS).map_err(|e| e.to_string())?;
        let mut server_bytes = Vec::new();
        safe_serialize(&server_key, &mut server_bytes, 1 << 32).map_err(|e| e.to_string())?;
        if !$a.key_output.is_empty() {
            std::fs::write(&$a.key_output, &server_bytes).map_err(|e| e.to_string())?;
        }
        let encrypt = |name: &str, x: &[u64], y: &[u64]| -> Vec<$ct> {
            let mut v = Vec::new();
            if name == "D64" || name == "V64" {
                for i in 0..64 {
                    v.push(<$ct>::encrypt(x[i] as $clear, &client_key));
                    if name == "D64" { v.push(<$ct>::encrypt(y[i] as $clear, &client_key)); }
                }
                if name == "V64" { for i in 0..64 { v.push(<$ct>::encrypt(y[i] as $clear, &client_key)); } }
            } else {
                v.push(<$ct>::encrypt(x[0] as $clear, &client_key));
                if matches!(name, "S-add" | "S-mul") || name.starts_with("CH") {
                    v.push(<$ct>::encrypt(y[0] as $clear, &client_key));
                }
            }
            v
        };
        let eval = |name: &str, v: &[$ct]| -> Vec<$ct> {
            match name {
                "S-add" => vec![&v[0] + &v[1]],
                "S-mul" => vec![&v[0] * &v[1]],
                "V64" => (0..64).map(|i| &v[i] * &v[i + 64]).collect(),
                "D64" => {
                    let products = (0..64).map(|i| &v[2 * i] * &v[2 * i + 1]).collect::<Vec<$ct>>();
                    vec![products.into_iter().sum::<$ct>()]
                }
                "P3" => {
                    let mut t = (&v[0] * 3 as $clear) + 2 as $clear;
                    t = (&t * &v[0]) + 5 as $clear;
                    vec![(&t * &v[0]) + 7 as $clear]
                }
                _ if name.starts_with("CH") => {
                    let mut t = v[0].clone();
                    for _ in 0..depth(name) { t = &t * &v[1]; }
                    vec![t]
                }
                _ if name.starts_with("SQ") => {
                    let mut t = v[0].clone();
                    for _ in 0..depth(name) { t = &t * &t; }
                    vec![t]
                }
                _ => panic!("unknown case"),
            }
        };
        let mut records = Vec::new();
        for fixture_index in 0..$a.fixture_count {
        let (x, y) = if fixture_index == 0 { ($x.clone(), $y.clone()) } else { inputs()? };
        check_shape(&$a, &x, &y)?;
        let encryption_start = Instant::now();
        let base = encrypt(&$a.case, &x, &y);
        let encryption_ms = encryption_start.elapsed().as_secs_f64() * 1000.0;
        let decrypt = |c: &$ct| -> u64 { c.decrypt(&client_key) };
        let mut warmup_values = Vec::new();
        let mut warmup_eval_ms = Vec::new();
        let mut warmup_decrypt_ms = Vec::new();
        pool.install(|| {
            for _ in 0..$a.warmups {
                let eval_start = Instant::now();
                let result = eval(&$a.case, &base);
                warmup_eval_ms.push(eval_start.elapsed().as_secs_f64() * 1000.0);
                let dec_start = Instant::now();
                for c in result {
                    warmup_values.push(decrypt(&c));
                }
                warmup_decrypt_ms.push(dec_start.elapsed().as_secs_f64() * 1000.0);
            }
        });
        let mut eval_ms = Vec::new();
        let mut decrypt_ms = Vec::new();
        let mut copy_ms = Vec::new();
        let mut output_bytes = Vec::new();
        let mut output_ciphertext_bytes = Vec::new();
        let mut values = Vec::new();
        pool.install(|| {
            for _ in 0..$a.repetitions {
                let copy_start = Instant::now();
                let input = base.clone();
                copy_ms.push(copy_start.elapsed().as_secs_f64() * 1000.0);
                let eval_start = Instant::now();
                let result = eval(&$a.case, &input);
                eval_ms.push(eval_start.elapsed().as_secs_f64() * 1000.0);
                let mut request_bytes = 0u64;
                let mut restored = Vec::new();
                for c in result {
                    let mut bytes = Vec::new();
                    safe_serialize(&c, &mut bytes, 1 << 30).expect("ciphertext serialization");
                    restored.push(safe_deserialize::<$ct>(bytes.as_slice(), 1 << 30).expect("ciphertext deserialization"));
                    request_bytes += bytes.len() as u64;
                    output_ciphertext_bytes.push(bytes.len() as u64);
                }
                let dec_start = Instant::now();
                for c in &restored {
                    values.push(decrypt(c));
                }
                decrypt_ms.push(dec_start.elapsed().as_secs_f64() * 1000.0);
                output_bytes.push(request_bytes);
            }
        });
        let e2e_start = Instant::now();
        let mut e2e_input = None;
        let mut e2e_output = None;
        let e2e_values = pool.install(|| {
            let input = encrypt(&$a.case, &x, &y);
            let result = eval(&$a.case, &input);
            let values = result.iter().map(&decrypt).collect::<Vec<u64>>();
            e2e_input = Some(input);
            e2e_output = Some(result);
            values
        });
        let e2e_ms = e2e_start.elapsed().as_secs_f64() * 1000.0;
        drop(e2e_input);
        drop(e2e_output);
        let input_bytes = base.iter().map(|c| {
            let mut b = Vec::new(); safe_serialize(c, &mut b, 1 << 30).expect("input serialization"); b.len() as u64
        }).sum::<u64>();
        let logical_outputs = if $a.case == "V64" { 64 } else { 1 };
        let record = serde_json::json!({
            "backend": format!("tfhe{}", $a.width),
            "case": $a.case,
            "source": "e8f3926bb53d7eea95e8a7f581f60aae1c7aba16",
            "parameter_alias": "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128",
            "parameters": serde_json::from_str::<serde_json::Value>(&parameter_json).expect("parameter JSON"),
            "encryption_key_model": "secret_client_key",
            "integer_semantics": format!("bounded inputs in FheUint{}, no full-width equivalence claim", $a.width),
            "serialization": "TFHE safe_serialize format 0.5, versioning 0.1, uncompressed",
            "requested_threads": $a.threads,
            "observed_threads": pool.current_num_threads(),
            "fresh_key_per_session": true,
            "build": "release, target-cpu=native, default-features=false, integer",
            "avx512_feature_compiled": cfg!(feature = "avx512"),
            "avx512_runtime_eligible": wide::avx512_runtime_eligible(),
            "fixture_index": fixture_index,
            "fixture_count": $a.fixture_count,
            "keygen_ms": if fixture_index == 0 { Some(keygen_ms) } else { None },
            "key_install_ms": if fixture_index == 0 { Some(key_install_ms) } else { None },
            "encryption_ms": encryption_ms,
            "e2e_ms": e2e_ms,
            "copy_reset_ms": copy_ms,
            "eval_ms": eval_ms,
            "decrypt_ms": decrypt_ms.clone(),
            "decrypt_batch_ms": decrypt_ms,
            "batch_size": 1,
            "input_bytes": input_bytes,
            "public_key_bytes": null,
            "server_key_bytes": server_bytes.len(),
            "output_bytes": output_bytes.clone(),
            "batch_output_bytes": output_bytes,
            "output_ciphertext_bytes": output_ciphertext_bytes,
            "logical_outputs": logical_outputs,
            "physical_input_ciphertexts": base.len(),
            "timing_units": "eval_ms=one evaluation, decrypt_ms=aggregate whole-request decryption, output_bytes=aggregate serialized bytes for that evaluation",
            "keygen_worker_pool": $a.threads,
            "expected_value_count": $a.repetitions * logical_outputs,
            "warmup_eval_ms": warmup_eval_ms,
            "warmup_decrypt_ms": warmup_decrypt_ms,
            "warmup_values": warmup_values,
            "values": values,
            "e2e_values": e2e_values
        });
        records.push(record);
        }
        records
    }};
}

macro_rules! selftest_for {
    ($ct:ty, $clear:ty, $width:expr, $output:expr) => {{
        let config = ConfigBuilder::default().use_custom_parameters(PARAMETERS).build();
        let (cks, sks) = generate_keys(config.clone());
        set_server_key(sks);
        let a = <$ct>::encrypt(7 as $clear, &cks);
        let b = <$ct>::encrypt(6 as $clear, &cks);
        let c = &a * &b;
        let mut bytes = Vec::new();
        safe_serialize(&c, &mut bytes, 1 << 30).map_err(|e| e.to_string())?;
        let round: $ct = safe_deserialize(bytes.as_slice(), 1 << 30).map_err(|e| e.to_string())?;
        let correct: $clear = round.decrypt(&cks);
        if correct != 42 { return Err("roundtrip mismatch".into()); }
        let truncated = safe_deserialize::<$ct>(&bytes[..bytes.len() - 1], 1 << 30).is_err();
        let (wrong_cks, wrong_sks) = generate_keys(config);
        let wrong = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            set_server_key(wrong_sks);
            let wrong: $ct = safe_deserialize(bytes.as_slice(), 1 << 30).expect("valid ciphertext encoding");
            let value: $clear = wrong.decrypt(&wrong_cks);
            value != 42
        })).unwrap_or(true);
        if !truncated || !wrong { return Err("negative control failed".into()); }
        let mut f = std::fs::File::create($output).map_err(|e| e.to_string())?;
        writeln!(f, "{}", serde_json::json!({"selftest":"PASS","width":$width,"ct_roundtrip":true,"truncated_rejected":truncated,"wrong_key_rejected":wrong,"ct_bytes":bytes.len()})).map_err(|e| e.to_string())?;
        write_rusage($output)?;
        Ok(())
    }};
}

fn selftest(output: &str, width: u8) -> Result<(), String> {
    match width {
        16 => selftest_for!(FheUint16, u16, 16, output),
        64 => selftest_for!(FheUint64, u64, 64, output),
        _ => Err("width must be 16 or 64".into()),
    }
}

fn run() -> Result<(), String> {
    let a = args()?;
    if a.build_info {
        println!("{}", serde_json::json!({
            "avx512_feature_compiled": cfg!(feature = "avx512"),
            "avx512_runtime_eligible": wide::avx512_runtime_eligible(),
            "build": "release, target-cpu=native, default-features=false, integer"
        }));
        return Ok(());
    }
    let mut output = std::fs::File::create(&a.output).map_err(|e| format!("cannot open output: {e}"))?;
    if a.selftest && a.wide { return wide::selftest(&a.output); }
    if a.selftest { return selftest(&a.output, a.width); }
    if a.wide {
        if !wide::is_wide_case(&a.case) { return Err("--wide requires a declared wide case".into()); }
        let (x, y) = wide::read_inputs()?;
        let results = wide::execute(&a, x, y)?;
        for result in results {
            writeln!(output, "{result}").map_err(|e| e.to_string())?;
        }
        write_rusage(&a.output)?;
        return Ok(());
    }
    let (x, y) = inputs()?;
    check_shape(&a, &x, &y)?;
    let results = match a.width {
        16 => execute!(a, x, y, FheUint16, u16),
        64 => execute!(a, x, y, FheUint64, u64),
        _ => return Err("width must be 16 or 64".into()),
    };
    for result in results {
        writeln!(output, "{result}").map_err(|e| e.to_string())?;
    }
    write_rusage(&a.output)?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("tfhe_bench: {e}");
        std::process::exit(2);
    }
}
