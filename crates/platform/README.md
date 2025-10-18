# fynx-platform

[![Crates.io](https://img.shields.io/crates/v/fynx-platform)](https://crates.io/crates/fynx-platform)
[![Documentation](https://docs.rs/fynx-platform/badge.svg)](https://docs.rs/fynx-platform)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](../../LICENSE-MIT)

Core platform types, traits, and utilities for the Fynx security ecosystem.

## Overview

`fynx-platform` provides the foundational types and traits used across all Fynx modules:

- **Unified Error Handling**: `FynxError` and `FynxResult<T>`
- **Core Traits**: `SecurityModule`, `Scanner`, `Analyzer`
- **Common Types**: `ScanResult`, `Finding`, `Match`, etc.

## Features

- Zero unsafe code
- Minimal dependencies
- Async-ready with `async-trait`
- Optional `serde` support

## Installation

```toml
[dependencies]
fynx-platform = "0.1"

# With serde support
fynx-platform = { version = "0.1", features = ["serde"] }
```

## Usage

### Error Handling

```rust
use fynx_platform::{FynxError, FynxResult};

fn my_function() -> FynxResult<String> {
    // Return Ok
    Ok("success".to_string())

    // Or return an error
    // Err(FynxError::Config("Invalid config".into()))
}
```

### Implementing SecurityModule

```rust
use fynx_platform::{SecurityModule, FynxResult};

struct MyModule;

impl SecurityModule for MyModule {
    fn id(&self) -> &'static str {
        "my_module"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn description(&self) -> &'static str {
        "My custom security module"
    }

    fn init(&mut self) -> FynxResult<()> {
        // Initialization logic
        Ok(())
    }
}
```

## Documentation

For detailed API documentation, see [docs.rs/fynx-platform](https://docs.rs/fynx-platform).

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](../../LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))

at your option.
