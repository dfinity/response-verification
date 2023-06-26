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

```shell
wasm-pack test --node packages/ic-response-verification --features=js
```

## Wasm Build

```shell
pnpm run --filter @dfinity/response-verification build
```

## Link NPM package

From the root of this repository:

```
pushd packages/ic-response-verification && sudo npm link && popd
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
