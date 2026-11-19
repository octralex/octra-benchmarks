use std::io::{self, Write};
use std::time::Instant;

use tfhe::integer::U256;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint128, FheUint256, FheUint32, FheUint64};

use super::{write_rusage, Args, PARAMETERS};

const P127: u128 = (1_u128 << 127) - 1;

pub fn is_wide_case(case: &str) -> bool {
    matches!(case, "I63-add" | "I63-mul" | "F127-add" | "F127-mul" | "D25-d1" | "D25-d2" | "D25-d4")
}

fn depth(case: &str) -> usize {
    case.strip_prefix("D25-d").unwrap().parse().unwrap()
}

fn input_count(case: &str) -> usize {
    if case.starts_with("D25-d") { depth(case) + 1 } else { 2 }
}

pub fn read_inputs() -> Result<(Vec<String>, Vec<String>), String> {
    let mut x = String::new();
    let mut y = String::new();
    if io::stdin().read_line(&mut x).map_err(|e| e.to_string())? == 0 {
        return Err("missing wide input vector".into());
    }
    io::stdin().read_line(&mut y).map_err(|e| e.to_string())?;
    let parse = |line: &str| -> Result<Vec<String>, String> {
        if line.trim().is_empty() { return Ok(Vec::new()); }
        line.split(',')
            .map(|s| {
                let value = s.trim();
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) ||
                    (value.len() > 1 && value.starts_with('0')) {
                    return Err("invalid canonical unsigned decimal or empty input token".to_string());
                }
                Ok(value.to_string())
            })
            .collect()
    };
    Ok((parse(&x)?, parse(&y)?))
}

fn check_domain(a: &Args, x: &[String], y: &[String]) -> Result<(), String> {
    let expected_x = if a.case.starts_with("D25-d") { 5 } else { 1 };
    if !is_wide_case(&a.case) || x.len() != expected_x {
        return Err("wide input shape or case mismatch".into());
    }
    let expected_y = if a.case.starts_with("D25-d") { 0 } else { 1 };
    if y.len() != expected_y {
        return Err("wide second-operand shape mismatch".into());
    }
    for value in x.iter().chain(y) {
        if a.case.starts_with("I63") {
            let parsed = value.parse::<u64>().map_err(|e| e.to_string())?;
            if parsed >= (1_u64 << 63) { return Err("I63 input outside domain".into()); }
        } else if a.case.starts_with("D25") {
            let parsed = value.parse::<u32>().map_err(|e| e.to_string())?;
            if parsed >= (1_u32 << 25) { return Err("D25 input outside domain".into()); }
        } else {
            let parsed = value.parse::<u128>().map_err(|e| e.to_string())?;
            if parsed >= P127 { return Err("F127 input is not canonical".into()); }
        }
    }
    Ok(())
}

fn decimal_words(mut words: Vec<u64>) -> String {
    if words.iter().all(|&word| word == 0) { return "0".into(); }
    let mut digits = Vec::new();
    while words.iter().any(|&word| word != 0) {
        let mut remainder = 0_u128;
        for word in words.iter_mut().rev() {
            let current = (remainder << 64) | (*word as u128);
            *word = (current / 10) as u64;
            remainder = current % 10;
        }
        digits.push((remainder as u8 + b'0') as char);
    }
    digits.iter().rev().collect()
}

trait WideClear: Copy {
    fn decimal(self) -> String;
    fn answer(self, case: &str) -> String;
}

impl WideClear for u64 {
    fn decimal(self) -> String { self.to_string() }
    fn answer(self, _case: &str) -> String { self.to_string() }
}

impl WideClear for u128 {
    fn decimal(self) -> String { self.to_string() }
    fn answer(self, case: &str) -> String {
        if case.starts_with("F127") { (self % P127).to_string() } else { self.to_string() }
    }
}

impl WideClear for U256 {
    fn decimal(self) -> String {
        let (low, high) = self.to_low_high_u128();
        decimal_words(vec![
            low as u64,
            (low >> 64) as u64,
            high as u64,
            (high >> 64) as u64,
        ])
    }
    fn answer(self, case: &str) -> String {
        if case.starts_with("F127") {
            (self % U256::from((P127, 0_u128))).decimal()
        } else {
            self.decimal()
        }
    }
}

fn terminal<T: WideClear>(case: &str, value: T) -> (String, String) {
    (value.decimal(), value.answer(case))
}

pub fn avx512_runtime_eligible() -> bool {
    #[cfg(all(feature = "avx512", any(target_arch = "x86", target_arch = "x86_64")))]
    {
        return std::arch::is_x86_feature_detected!("avx512f") &&
            std::arch::is_x86_feature_detected!("avx512dq") &&
            std::arch::is_x86_feature_detected!("avx512bw") &&
            std::arch::is_x86_feature_detected!("avx512vl");
    }
    #[cfg(not(all(feature = "avx512", any(target_arch = "x86", target_arch = "x86_64"))))]
    false
}

macro_rules! execute_typed {
    ($a:expr, $x:expr, $y:expr, $in_ct:ty, $out_ct:ty, $out_clear:ty,
     $encrypt:expr, $evaluate:expr, $representation:expr) => {{
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
        let encrypt = $encrypt;
        let evaluate = $evaluate;
        let mut records = Vec::new();
        for fixture_index in 0..$a.fixture_count {
            let (x, y) = if fixture_index == 0 { ($x.clone(), $y.clone()) } else { read_inputs()? };
            check_domain(&$a, &x, &y)?;
            let encryption_start = Instant::now();
            let base: Vec<$in_ct> = encrypt(&client_key, &x, &y);
            let encryption_ms = encryption_start.elapsed().as_secs_f64() * 1000.0;
            let decrypt = |c: &$out_ct| -> (String, String) {
                let clear: $out_clear = c.decrypt(&client_key);
                terminal(&$a.case, clear)
            };
            let mut warmup_values = Vec::new();
            let mut warmup_lift = Vec::new();
            let mut warmup_eval_ms = Vec::new();
            let mut warmup_decrypt_ms = Vec::new();
            pool.install(|| {
                for _ in 0..$a.warmups {
                    let eval_start = Instant::now();
                    let results: Vec<$out_ct> = evaluate(&base);
                    warmup_eval_ms.push(eval_start.elapsed().as_secs_f64() * 1000.0);
                    let dec_start = Instant::now();
                    for c in results {
                        let (lift, answer) = decrypt(&c);
                        warmup_lift.push(lift);
                        warmup_values.push(answer);
                    }
                    warmup_decrypt_ms.push(dec_start.elapsed().as_secs_f64() * 1000.0);
                }
            });
            let mut eval_ms = Vec::new();
            let mut decrypt_ms = Vec::new();
            let mut decrypt_batch_ms = Vec::new();
            let mut copy_ms = Vec::new();
            let mut output_bytes = Vec::new();
            let mut batch_output_bytes = Vec::new();
            let mut output_ciphertext_bytes = Vec::new();
            let mut values = Vec::new();
            let mut lift_values = Vec::new();
            pool.install(|| {
                for _ in 0..$a.repetitions {
                    let copy_start = Instant::now();
                    let input = base.clone();
                    copy_ms.push(copy_start.elapsed().as_secs_f64() * 1000.0);
                    let eval_start = Instant::now();
                    let mut evaluations = Vec::new();
                    for _ in 0..$a.batch { evaluations.push(evaluate(&input)); }
                    eval_ms.push(eval_start.elapsed().as_secs_f64() * 1000.0 / $a.batch as f64);
                    let mut batch_dec_ms = 0.0;
                    let mut batch_bytes = 0_u64;
                    for results in evaluations {
                        let mut request_bytes = 0_u64;
                        let mut restored = Vec::new();
                        for c in results {
                            let mut bytes = Vec::new();
                            safe_serialize(&c, &mut bytes, 1 << 32).expect("wide ciphertext serialization");
                            restored.push(safe_deserialize::<$out_ct>(bytes.as_slice(), 1 << 32).expect("wide ciphertext deserialization"));
                            request_bytes += bytes.len() as u64;
                            output_ciphertext_bytes.push(bytes.len() as u64);
                        }
                        let dec_start = Instant::now();
                        for c in &restored {
                            let (lift, answer) = decrypt(c);
                            lift_values.push(lift);
                            values.push(answer);
                        }
                        batch_dec_ms += dec_start.elapsed().as_secs_f64() * 1000.0;
                        batch_bytes += request_bytes;
                    }
                    decrypt_ms.push(batch_dec_ms / $a.batch as f64);
                    decrypt_batch_ms.push(batch_dec_ms);
                    output_bytes.push(batch_bytes / $a.batch as u64);
                    batch_output_bytes.push(batch_bytes);
                }
            });
            let e2e_start = Instant::now();
            let mut e2e_input = None;
            let mut e2e_output = None;
            let (e2e_values, e2e_lift) = pool.install(|| {
                let input: Vec<$in_ct> = encrypt(&client_key, &x, &y);
                let results: Vec<$out_ct> = evaluate(&input);
                let mut values = Vec::new();
                let mut lifts = Vec::new();
                for c in &results {
                    let (lift, answer) = decrypt(c);
                    lifts.push(lift);
                    values.push(answer);
                }
                e2e_input = Some(input);
                e2e_output = Some(results);
                (values, lifts)
            });
            let e2e_ms = e2e_start.elapsed().as_secs_f64() * 1000.0;
            drop(e2e_input);
            drop(e2e_output);
            let input_bytes = base.iter().map(|c| {
                let mut bytes = Vec::new();
                safe_serialize(c, &mut bytes, 1 << 32).expect("wide input serialization");
                bytes.len() as u64
            }).sum::<u64>();
            let record = serde_json::json!({
                "backend": "tfhe-wide",
                "case": $a.case,
                "source": "e8f3926bb53d7eea95e8a7f581f60aae1c7aba16",
                "parameter_alias": "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128",
                "parameters": serde_json::from_str::<serde_json::Value>(&parameter_json).expect("parameter JSON"),
                "representation": $representation,
                "input_container": stringify!($in_ct),
                "output_container": stringify!($out_ct),
                "encryption_key_model": "secret_client_key",
                "integer_semantics": "narrow encrypted inputs, public zero extension before multiplication, full lifted output and exact client reduction",
                "serialization": "TFHE safe_serialize format 0.5, versioning 0.1, uncompressed",
                "requested_threads": $a.threads,
                "observed_threads": pool.current_num_threads(),
                "fresh_key_per_session": true,
                "build": "release, target-cpu=native, default-features=false, integer",
                "avx512_feature_compiled": cfg!(feature = "avx512"),
                "avx512_runtime_eligible": avx512_runtime_eligible(),
                "fixture_index": fixture_index,
                "fixture_count": $a.fixture_count,
                "keygen_ms": if fixture_index == 0 { Some(keygen_ms) } else { None },
                "key_install_ms": if fixture_index == 0 { Some(key_install_ms) } else { None },
                "encryption_ms": encryption_ms,
                "e2e_ms": e2e_ms,
                "copy_reset_ms": copy_ms,
                "eval_ms": eval_ms,
                "decrypt_ms": decrypt_ms.clone(),
                "decrypt_batch_ms": decrypt_batch_ms,
                "batch_size": $a.batch,
                "input_bytes": input_bytes,
                "public_key_bytes": null,
                "server_key_bytes": server_bytes.len(),
                "output_bytes": output_bytes.clone(),
                "batch_output_bytes": batch_output_bytes,
                "output_ciphertext_bytes": output_ciphertext_bytes,
                "logical_outputs": 1,
                "physical_input_ciphertexts": base.len(),
                "physical_output_ciphertexts": 1,
                "timing_units": "eval_ms=mean per evaluation including casts, decrypt_ms=mean decrypt plus exact client reduction, output_bytes=mean serialized bytes, batch_output_bytes=aggregate bytes per timed batch",
                "keygen_worker_pool": $a.threads,
                "expected_value_count": $a.repetitions * $a.batch,
                "warmup_eval_ms": warmup_eval_ms,
                "warmup_decrypt_ms": warmup_decrypt_ms,
                "warmup_values_decimal": warmup_values,
                "values_decimal": values,
                "e2e_values_decimal": e2e_values,
                "warmup_lift_decimal": warmup_lift,
                "lift_decimal": lift_values,
                "e2e_lift_decimal": e2e_lift
            });
            records.push(record);
        }
        records
    }};
}

pub fn execute(a: &Args, x: Vec<String>, y: Vec<String>) -> Result<Vec<serde_json::Value>, String> {
    check_domain(a, &x, &y)?;
    let results = match a.case.as_str() {
        "I63-add" => execute_typed!(a, x, y, FheUint64, FheUint64, u64,
            |cks: &ClientKey, x: &Vec<String>, y: &Vec<String>| vec![
                FheUint64::encrypt(x[0].parse::<u64>().unwrap(), cks),
                FheUint64::encrypt(y[0].parse::<u64>().unwrap(), cks),
            ],
            |v: &Vec<FheUint64>| -> Vec<FheUint64> { vec![&v[0] + &v[1]] },
            "FheUint64 exact 64-bit sum"),
        "I63-mul" => execute_typed!(a, x, y, FheUint64, FheUint128, u128,
            |cks: &ClientKey, x: &Vec<String>, y: &Vec<String>| vec![
                FheUint64::encrypt(x[0].parse::<u64>().unwrap(), cks),
                FheUint64::encrypt(y[0].parse::<u64>().unwrap(), cks),
            ],
            |v: &Vec<FheUint64>| -> Vec<FheUint128> {
                let a: FheUint128 = v[0].clone().cast_into();
                let b: FheUint128 = v[1].clone().cast_into();
                vec![&a * &b]
            },
            "FheUint64 inputs, public zero extension to FheUint128 before multiplication"),
        "F127-add" => execute_typed!(a, x, y, FheUint128, FheUint128, u128,
            |cks: &ClientKey, x: &Vec<String>, y: &Vec<String>| vec![
                FheUint128::encrypt(x[0].parse::<u128>().unwrap(), cks),
                FheUint128::encrypt(y[0].parse::<u128>().unwrap(), cks),
            ],
            |v: &Vec<FheUint128>| -> Vec<FheUint128> { vec![&v[0] + &v[1]] },
            "FheUint128 lifted sum, client final Mersenne reduction"),
        "F127-mul" => execute_typed!(a, x, y, FheUint128, FheUint256, U256,
            |cks: &ClientKey, x: &Vec<String>, y: &Vec<String>| vec![
                FheUint128::encrypt(x[0].parse::<u128>().unwrap(), cks),
                FheUint128::encrypt(y[0].parse::<u128>().unwrap(), cks),
            ],
            |v: &Vec<FheUint128>| -> Vec<FheUint256> {
                let a: FheUint256 = v[0].clone().cast_into();
                let b: FheUint256 = v[1].clone().cast_into();
                vec![&a * &b]
            },
            "FheUint128 inputs, public zero extension to FheUint256 before multiplication, client final Mersenne reduction"),
        "D25-d1" | "D25-d2" | "D25-d4" => execute_typed!(a, x, y, FheUint32, FheUint128, u128,
            |cks: &ClientKey, x: &Vec<String>, _y: &Vec<String>| x[..input_count(&a.case)].iter().map(|value| {
                FheUint32::encrypt(value.parse::<u32>().unwrap(), cks)
            }).collect::<Vec<FheUint32>>(),
            |v: &Vec<FheUint32>| -> Vec<FheUint128> {
                let wide: Vec<FheUint128> = v.iter().map(|value| value.clone().cast_into()).collect();
                let mut acc = wide[0].clone();
                for value in &wide[1..] { acc = &acc * value; }
                vec![acc]
            },
            "FheUint32 inputs, common FheUint128 result representation, sequential left fold"),
        _ => return Err("unknown wide case".into()),
    };
    Ok(results)
}

pub fn selftest(output: &str) -> Result<(), String> {
    let a = Args {
        case: "F127-mul".into(),
        output: output.into(),
        repetitions: 1,
        warmups: 1,
        threads: 1,
        batch: 1,
        fixture_count: 1,
        ..Default::default()
    };
    let input = (P127 - 1).to_string();
    let records = execute(&a, vec![input.clone()], vec![input])?;
    let expected_lift = "28948022309329048855892746252171976962636931432568264082937646787114745987076";
    if records[0]["values_decimal"][0] != "1" || records[0]["lift_decimal"][0] != expected_lift {
        return Err("full-width TFHE selftest mismatch".into());
    }
    let value = U256::from((P127 - 1, 0_u128)) * U256::from((P127 - 1, 0_u128));
    let full = value % U256::from((P127, 0_u128));
    let truncated = value.to_low_high_u128().0 % P127;
    if full.decimal() != "1" || truncated != 4 {
        return Err("TFHE truncation control lost its counterexample".into());
    }
    let mut file = std::fs::File::create(output).map_err(|e| e.to_string())?;
    writeln!(file, "{}", serde_json::json!({
        "selftest": "PASS",
        "wide_full_product": true,
        "full_product_residue": full.decimal(),
        "truncated_128_residue": truncated.to_string(),
        "ct_roundtrip": true
    })).map_err(|e| e.to_string())?;
    write_rusage(output)?;
    Ok(())
}
