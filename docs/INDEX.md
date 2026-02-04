# Documentation Index

## 📚 Core Documentation

| Document | Purpose |
|----------|---------|
| [README.md](../README.md) | Quick start, features, usage |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | Internal design, extension points |
| [CHANGELOG.md](../CHANGELOG.md) | Version history, releases |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution guidelines |

## 🎯 Quick Links

- **Getting Started**: [README.md](../README.md#installation)
- **Add Backend**: [ARCHITECTURE.md](../ARCHITECTURE.md#adding-a-new-backend)
- **Add Attack**: [ARCHITECTURE.md](../ARCHITECTURE.md#adding-a-new-attack)
- **API Docs**: Run `cargo doc --open`

## 📖 By Topic

### Backends
- [Circom](../src/targets/circom.rs)
- [Noir](../src/targets/noir.rs)
- [Halo2](../src/targets/halo2.rs)
- [Cairo](../src/targets/cairo.rs)

### Attacks
- [Underconstrained](../src/attacks/underconstrained.rs)
- [Soundness](../src/attacks/soundness.rs)
- [Arithmetic](../src/attacks/arithmetic.rs)

### Examples
- [Campaign Configs](../tests/campaigns/)
- [Attack Patterns](../templates/)
