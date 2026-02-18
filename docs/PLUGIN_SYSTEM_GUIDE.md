# Plugin System Guide

This guide documents how dynamic attack plugins are discovered, loaded, selected, and enforced in strict engagements.

## Prerequisites

- Build the host binary with dynamic plugin loading enabled:
  - `cargo run --features attack-plugins -- --config <campaign.yaml>`
- Build plugins as `cdylib` libraries.
- Export the required symbol from each plugin library:
  - `zk_attacks_plugins`
- Keep host + plugin toolchains aligned. The plugin interface uses Rust ABI trait objects, so version/toolchain drift can break loading.

## Discovery Paths

Plugins are loaded from `campaign.parameters.additional.attack_plugin_dirs`.

Supported shapes:

- YAML sequence:
  - `attack_plugin_dirs: ["/opt/zkfuzz/plugins", "/opt/zkfuzz/custom/my_plugin.so"]`
- Comma-separated string:
  - `attack_plugin_dirs: "/opt/zkfuzz/plugins,/opt/zkfuzz/custom/my_plugin.so"`

Resolution behavior:

- Directory paths are scanned for dynamic libraries at one level.
- File paths are loaded directly when extension matches platform conventions:
  - Linux: `.so`
  - macOS: `.dylib`
  - Windows: `.dll`

## Per-Attack Plugin Selection

For each configured attack, plugin name is resolved in this order:

1. `attacks[].plugin`
2. `attacks[].config.plugin`

If a plugin name is present:

- Engine tries exact registry lookup, then lowercased lookup.
- If found, plugin executes for that attack.
- If plugin was explicitly requested and ran, built-in attack handler is not executed for that same attack entry.

If a plugin name is present but not found:

- `engagement_strict: true` -> hard error; run aborts.
- `engagement_strict: false` -> warning; engine continues and can fall back to built-in attack handling.

## Strict-Mode Behavior

Strict engagement safeguards relevant to plugins:

- Missing explicit plugin is a contract violation and fails the run.
- Any configured attack that does not execute (plugin missing and no runnable fallback) fails strict mode.

Recommended strict settings for production engagements:

```yaml
campaign:
  parameters:
    additional:
      evidence_mode: true
      engagement_strict: true
      strict_backend: true
      attack_plugin_dirs:
        - "/opt/zkfuzz/plugins"
```

## Minimal Example

```yaml
attacks:
  - type: boundary
    description: "Run boundary checks through external plugin"
    plugin: example_plugin
    config:
      samples: 64

campaign:
  parameters:
    additional:
      attack_plugin_dirs:
        - "./target/release"
      engagement_strict: true
```

Build example plugin:

```bash
cargo build -p zk-attacks-plugin-example --release
```

## Operational Safeguards

- Load only trusted plugin binaries (signed or checksum-pinned in CI/CD).
- Use absolute, read-only plugin directories in production.
- Avoid writable plugin paths inside shared workspaces.
- Run with least privilege (isolated user/container, minimal filesystem scope).
- Keep plugin dependency set and Rust toolchain pinned with the host release.
- Prefer explicit plugin names per attack instead of implicit behavior.

## Troubleshooting

- `dynamic plugin loading is not enabled`:
  - Run/build with `--features attack-plugins`.
- `Missing zk_attacks_plugins`:
  - Export the required symbol from the plugin library.
- `attack plugin '<name>' not found in registry`:
  - Verify `attack_plugin_dirs`, library extension, and plugin metadata name.
  - In strict mode this is fatal by design.
