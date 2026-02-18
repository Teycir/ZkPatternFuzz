pub(crate) const BASIC_CAMPAIGN_YAML: &str = r#"
campaign:
  name: "Test"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./test.circom"
    main_component: "Main"

inputs:
  - name: "x"
    type: "field"
    interesting: ["0", "1"]

attacks:
  - type: "underconstrained"
    description: "Test"
"#;
