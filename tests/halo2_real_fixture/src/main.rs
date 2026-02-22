use std::env;
use std::process;

const INFO_JSON: &str = r#"{
  "name": "local_halo2_real_fixture",
  "k": 5,
  "num_advice_columns": 2,
  "num_fixed_columns": 1,
  "num_instance_columns": 1,
  "num_constraints": 1,
  "num_private_inputs": 2,
  "num_public_inputs": 1,
  "num_lookups": 0
}"#;

const CONSTRAINTS_JSON: &str = r#"{
  "gates": [
    {
      "wires": [0, 0, 0],
      "selectors": { "q_l": "1", "q_r": "0", "q_o": "-1", "q_m": "0", "q_c": "0" }
    }
  ]
}"#;

fn print_help() {
    println!("local_halo2_real_fixture");
    println!("Supported flags:");
    println!("  --help");
    println!("  --info");
    println!("  --constraints");
}

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("--help") => {
            print_help();
        }
        Some("--info") => {
            println!("{INFO_JSON}");
        }
        Some("--constraints") => {
            println!("{CONSTRAINTS_JSON}");
        }
        Some(flag) => {
            eprintln!("unsupported flag: {flag}");
            process::exit(2);
        }
    }
}
