# Response Verification Rust Crate

## Build

```shell
cargo build -p ic-response-verification
```

## Test

```shell
cargo test -p ic-response-verification
```

## Wasm Test

```
wasm-pack test --node packages/ic-response-verification
```

## Wasm Build

```
./scripts/package.sh
```

## Link NPM package

From the root of this repository:

```
pushd pkg && sudo npm link && popd
```

From another project:

```shell
npm link @dfinity/response-verification
```

## Format

Format rust files.

```shell
cargo fmt -p ic-response-verification
```

## Build docs

```shell
cargo doc -p ic-response-verification --no-deps --open
```
