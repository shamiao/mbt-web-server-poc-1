# mbt-web-server-poc-1

web server development proof-of-concept in MoonBit language

## Run

Rust language toolchain is required. In `server-runtime` directory, run:

```shell
cargo run -- app_example.wasm
```

Visit <http://127.0.0.1:8000/any-path> in browser.

To build the WASM file, MoonBit language toolchain is required. In `app` directory, run:

```shell
moon build
```

WASM output can be found in `target/wasm/release/build/main/main.wasm`.
