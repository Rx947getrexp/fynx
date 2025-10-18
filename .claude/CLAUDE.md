# Fynx Development Guidelines

## Philosophy

### Core Beliefs

- **Security First** - Every decision prioritizes security and correctness
- **Incremental progress over big bangs** - Small changes that compile and pass tests
- **Learning from existing code** - Study and plan before implementing
- **Pragmatic over dogmatic** - Adapt to project reality
- **Clear intent over clever code** - Be boring and obvious

### Simplicity Means

- Single responsibility per function/struct
- Avoid premature abstractions
- No clever tricks - choose the boring solution
- If you need to explain it, it's too complex
- **Unified platform** - No duplicate types across modules (use `fynx-platform`)

## Process

### 1. Pre-Development Requirements

**MANDATORY**: Before starting any development work:

1. **Read ALL project documentation in sequence**:

   **Core Technical Documents** (Read FIRST):
   - `README.md` - Project overview, features, and quick start
   - `docs/ARCHITECTURE.md` - System architecture and module design
   - `docs/MODULE_DESIGN.md` - Module development standards and interfaces
   - `docs/NAMING.md` - Naming conventions and code style
   - `Cargo.toml` - Workspace configuration and dependencies

   **Development & Quality Documents**:
   - `docs/STANDARDS.md` - Development processes, CI/CD, and quality gates
   - `docs/SECURITY.md` - Security policy and OpenSSF compliance
   - `CONTRIBUTING.md` - Contribution guidelines (if exists)
   - `CHANGELOG.md` - Version history and changes

   **Module-Specific Documents**:
   - `crates/<module>/README.md` - Module-specific documentation
   - `crates/<module>/Cargo.toml` - Module dependencies and features

2. **Document Reading Verification**:
   - **Before any coding**: Confirm you have read ALL listed documents
   - **Cross-reference understanding**: Check for conflicts between documents
   - **Identify gaps**: Note any missing information that needs clarification
   - **Document your understanding**: Summarize key requirements from multiple sources

3. **NO SIMPLIFICATION ALLOWED**:
   - **NEVER** skip features or requirements to "simplify" development
   - **NEVER** compromise on OpenSSF Level 5 standards
   - **NEVER** bypass security checks, testing, or documentation
   - **NEVER** create shortcuts that violate architectural principles
   - **NEVER** rely on only one document when multiple sources exist
   - If complexity seems overwhelming, break into smaller stages, don't simplify

### 2. Planning & Staging

Break complex work into 3-5 stages. Document in `IMPLEMENTATION_PLAN.md`:

```markdown
## Stage N: [Name]
**Module**: [platform/proto/protect/detect/exploit]
**Goal**: [Specific deliverable]
**Success Criteria**: [Testable outcomes]
**Tests**: [Specific test cases]
**Security Review**: [Required? Y/N]
**Status**: [Not Started|In Progress|Complete]
```

- Update status as you progress
- Mark security-sensitive code for review
- Remove file when all stages are done

### 3. Implementation Flow

1. **Complete Document Review** - Read ALL documentation in sequence (see section 1)
   - Understand module boundaries and interfaces
   - Check `fynx-platform` for existing types
   - Review security requirements for your module

2. **Codebase Analysis** - Study existing patterns
   - Check if similar functionality exists in other modules
   - Identify reusable components from `fynx-platform`
   - Review existing tests for patterns

3. **Requirements Validation** - Ensure complete understanding
   - Cross-check requirements across docs
   - Verify OpenSSF compliance requirements
   - Confirm security implications

4. **Test** - Write test first (TDD when possible)
5. **Implement** - Complete code to pass ALL requirements
6. **Security Review** - Check for security issues
7. **Refactor** - Clean up with tests passing
8. **Commit** - With clear conventional commit message

### 4. When Stuck (After 3 Attempts)

**CRITICAL**: Maximum 3 attempts per issue, then STOP.

1. **Document what failed**:
   - What you tried
   - Specific error messages
   - Why you think it failed

2. **Research alternatives**:
   - Check similar implementations in Rust security ecosystem
   - Look at reference implementations (OpenSSH, rustls, etc.)
   - Note different approaches used

3. **Question fundamentals**:
   - Is this the right abstraction level?
   - Can this be split into smaller problems?
   - Is there a simpler approach entirely?

4. **Try different angle**:
   - Different crate/library?
   - Different architectural pattern?
   - Remove abstraction instead of adding?

## Technical Standards

### Architecture Principles

- **Composition over inheritance** - Use traits and generics
- **Trait-based interfaces** - Enable testing and flexibility
- **Explicit over implicit** - Clear data flow and dependencies
- **Test-driven when possible** - Never disable tests, fix them
- **Zero unsafe (when possible)** - Justify every `unsafe` block

### Code Quality

- **Every commit must**:
  - Compile successfully (`cargo build --all-features`)
  - Pass all tests (`cargo test --all-features --workspace`)
  - Pass clippy (`cargo clippy -- -D warnings`)
  - Be formatted (`cargo fmt`)
  - Pass security audit (`cargo audit`)
  - **Have complete documentation** (`cargo doc --no-deps`)

- **Before committing**:
  - Run formatters/linters
  - Self-review changes
  - Ensure commit message follows Conventional Commits
  - Check for sensitive data (keys, passwords, etc.)

### Error Handling

- Fail fast with descriptive messages
- Include context for debugging
- Handle errors at appropriate level
- Never silently swallow errors
- **Use unified error types**: `FynxResult<T>` and `FynxError` from `fynx-platform`
- **Never panic in library code** - Return `Result` instead

### Security Standards

- **Input validation**: Always validate untrusted input
- **Resource limits**: Prevent DoS (max packet size, timeouts)
- **Constant-time operations**: Use for crypto comparisons
- **Zeroize secrets**: Clear sensitive data from memory
- **No hardcoded credentials**: Use configuration
- **Audit dependencies**: Only use trusted crates

## Module-Specific Guidelines

### platform Module

- **Core responsibility**: Provide common types and traits
- **No functional logic**: Only definitions and utilities
- **Minimal dependencies**: Keep dependency tree small
- **Stable API**: Changes here affect all modules

### proto Module

- **Protocol compliance**: Follow RFCs strictly
- **Interoperability**: Test against reference implementations
- **Packet parsing**: Always validate, never trust input
- **Crypto**: Use established libraries (ring, rustls)

### protect Module

- **Documentation**: Explain obfuscation techniques clearly
- **Platform-specific**: Handle OS differences gracefully
- **Testing**: Difficult to test, use integration tests

### detect Module

- **Pattern matching**: Optimize for speed
- **Memory efficiency**: Handle large files/streams
- **Rule validation**: Validate rules before execution

### exploit Module

- **Ethical use**: Document legitimate use cases only
- **Rate limiting**: Implement respectful scanning
- **Legal compliance**: No weaponization

## Decision Framework

When multiple valid approaches exist, choose based on:

1. **Security** - Is this approach secure?
2. **Testability** - Can I easily test this?
3. **Readability** - Will someone understand this in 6 months?
4. **Consistency** - Does this match project patterns?
5. **Simplicity** - Is this the simplest solution that works?
6. **Performance** - Is this fast enough? (measure, don't guess)

## Project Integration

### Learning the Codebase

- **Documentation-First Approach** - Always read docs before code
- Find similar features in existing modules
- Check `fynx-platform` for reusable types
- Follow existing test patterns
- **Module boundaries**: Understand what goes where
- **Cross-reference with specs**: Ensure code matches docs

### Tooling

Required tools:
```bash
rustup component add rustfmt clippy
cargo install cargo-audit cargo-deny cargo-fuzz
```

- Use project's rustfmt.toml
- Use project's clippy configuration
- Don't introduce new dependencies without discussion

## Quality Gates

### Definition of Done

- [ ] Tests written and passing (≥80% coverage)
- [ ] Code follows project conventions
- [ ] No clippy warnings
- [ ] Formatted with rustfmt
- [ ] Security audit passed
- [ ] **All public APIs documented with rustdoc**
- [ ] **Module-level docs (`//!`) present**
- [ ] **Examples in docs are tested (doctest)**
- [ ] Examples provided (if new feature)
- [ ] CHANGELOG updated
- [ ] Commit messages follow Conventional Commits
- [ ] No TODOs without issue numbers

### Test Guidelines

- Test behavior, not implementation
- One assertion per test when possible
- Clear test names: `test_<module>_<scenario>_<expected>`
- Use existing test utilities
- Tests must be deterministic
- **Security tests**: Test boundary conditions and malicious input

## Important Reminders

**NEVER**:
- Use `--no-verify` to bypass commit hooks
- Disable tests instead of fixing them
- Commit code that doesn't compile
- Use `unwrap()` or `expect()` in library code
- Create duplicate types (check `fynx-platform` first)
- Skip security reviews for sensitive code
- **Simplify requirements to speed development**
- **Bypass OpenSSF compliance checks**
- **Introduce unsafe code without SAFETY comments**

**ALWAYS**:
- **Read ALL documentation before starting**
- **Use FynxResult<T> and FynxError from fynx-platform**
- **Implement complete functionality as specified**
- **Follow OpenSSF Level 5 standards**
- **Document security-sensitive code**
- Commit working code incrementally
- Update documentation as you code
- Run full test suite before pushing
- Check for existing implementations
- Use unified error handling patterns

## Module Checklist

Before creating/modifying a module:

- [ ] Does this belong in an existing module?
- [ ] Have I checked `fynx-platform` for existing types?
- [ ] Have I read the module's README?
- [ ] Do I understand the module's security requirements?
- [ ] Have I checked feature flags?
- [ ] Have I updated module documentation?
- [ ] Have I added examples?
- [ ] Have I considered cross-platform compatibility?

## OpenSSF Compliance Reminders

Every contribution must maintain OpenSSF Level 5 compliance:

- [ ] Security policy followed (SECURITY.md)
- [ ] Dependencies audited (cargo audit)
- [ ] Static analysis passed (clippy)
- [ ] Test coverage ≥80%
- [ ] Documentation complete
- [ ] No known vulnerabilities
- [ ] Code reviewed by another developer

## References

- [Project Documentation](docs/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)

---

**Remember**: Fynx is a security-focused project. When in doubt, prioritize security over convenience.

**Last Updated**: 2025-01-17
**Version**: 0.1.0
