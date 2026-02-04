# Contributing to ZkPatternFuzz

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to ZkPatternFuzz.

## Quick Links

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

Be respectful, inclusive, and professional. We're all here to improve ZK security.

## Getting Started

### Prerequisites

- Rust 1.70+ with 2021 edition
- Z3 SMT solver (for symbolic execution)
- Optional: circom, nargo, scarb (for backend testing)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ZkPatternFuzz.git
cd ZkPatternFuzz

# Build the project
cargo build

# Run tests
cargo test

# Run with example campaign
cargo run -- --config tests/campaigns/mock_merkle_audit.yaml
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Changes

Follow Rust best practices:
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Add tests for new functionality
- Update documentation

### 3. Test Your Changes

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with logging
RUST_LOG=debug cargo test

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy -- -D warnings
```

### 4. Commit Changes

Use clear, descriptive commit messages:

```bash
git commit -m "feat: add collision detection for hash outputs"
git commit -m "fix: correct coverage calculation for Halo2 circuits"
git commit -m "docs: improve symbolic execution examples"
```

Commit message prefixes:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

## Areas for Contribution

### High Priority

1. **Backend Integration Testing**
   - Add real circuit examples for each backend
   - Test with actual circom/nargo/scarb installations
   - Document setup requirements

2. **SARIF Report Format**
   - Implement SARIF 2.1.0 output
   - Add IDE integration examples

3. **Attack Implementations**
   - Complete collision detection
   - Complete boundary value testing
   - Add new attack patterns

### Medium Priority

4. **Documentation**
   - Add more examples
   - Create video tutorials
   - Write blog posts about findings

5. **Performance**
   - Optimize hot paths
   - Reduce lock contention
   - Improve corpus eviction

6. **CI/CD Integration**
   - GitHub Actions templates
   - GitLab CI examples
   - Docker images

### Low Priority

7. **Advanced Features**
   - Distributed fuzzing
   - Formal verification integration

## Testing

### Unit Tests

Add tests in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        // Test implementation
    }
}
```

### Integration Tests

Add tests in `tests/` directory:

```rust
#[tokio::test]
async fn test_integration() {
    // Integration test
}
```

### Backend Tests

Mark tests requiring backends as ignored:

```rust
#[tokio::test]
#[ignore = "Requires circom installation"]
async fn test_circom_backend() {
    // Backend-specific test
}
```

Run ignored tests with:
```bash
cargo test -- --ignored
```

## Documentation

### Code Documentation

Use rustdoc comments:

```rust
/// Brief description
///
/// # Arguments
///
/// * `param` - Parameter description
///
/// # Returns
///
/// Return value description
///
/// # Example
///
/// ```
/// let result = function(param);
/// ```
pub fn function(param: Type) -> Result<Type> {
    // Implementation
}
```

### Generate Documentation

```bash
cargo doc --open
```

## Pull Request Process

### Before Submitting

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] `cargo fmt` applied
- [ ] `cargo clippy` passes
- [ ] CHANGELOG.md updated (for significant changes)

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Changelog updated
```

### Review Process

1. Submit PR with clear description
2. Automated checks run (CI)
3. Code review by maintainers
4. Address feedback
5. Approval and merge

## Adding a New Backend

See [ARCHITECTURE.md](ARCHITECTURE.md#adding-a-new-backend) for detailed instructions.

Quick steps:
1. Implement `TargetCircuit` trait in `src/targets/`
2. Add to `ExecutorFactory`
3. Update `Framework` enum
4. Add tests
5. Document setup requirements

## Adding a New Attack

See [ARCHITECTURE.md](ARCHITECTURE.md#adding-a-new-attack) for detailed instructions.

Quick steps:
1. Create module in `src/attacks/`
2. Implement `Attack` trait
3. Register in attack dispatcher
4. Add configuration schema
5. Add tests and examples

## Style Guide

### Rust Code

Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):
- Use descriptive names
- Prefer `Result` over `panic!`
- Document public APIs
- Use `#[must_use]` where appropriate

### Error Handling

```rust
use anyhow::{Context, Result};

fn operation() -> Result<T> {
    something()
        .context("Failed to do something")?;
    Ok(result)
}
```

### Logging

```rust
use tracing::{info, warn, error, debug};

info!("Starting operation");
debug!("Detailed information: {:?}", data);
warn!("Potential issue detected");
error!("Operation failed: {}", err);
```

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to ZK security! 🔐
