# Response Verification Rust Crate

## Build

```shell
$ bazel build //ic-response-verification-rs:lib
```

## Test

```shell
$ bazel test //ic-response-verification-rs:lib_test
```

## Format

Format rust files.

```shell
$ bazel run @rules_rust//:rustfmt
```
