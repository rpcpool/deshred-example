# deshred-example
Example of receiving shreds on a UDP port and turning them into transactions

## Use it from your own program

```toml
[dependencies]
deshred = { git = "https://github.com/rpcpool/deshred-example", default-features = false }
```

`deshred` is a plain Rust library, so it links statically into your binary as an rlib with
no extra configuration. The dependency key is the package name `deshred`, not the repo
name. `default-features = false` drops the CLI-only deps (clap, ctrlc, env_logger); no
library code needs them.

`examples/minimal` is a standalone crate that consumes the library exactly this way:

```bash
cargo run --release -p deshred-minimal -- 0.0.0.0:20000
```
