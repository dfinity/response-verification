# Response Verification NPM Package

## Build

```shell
bazel build //ic-response-verification-ts:lib
```

If lockfiles need to be updated:
```shell
CARGO_BAZEL_REPIN=true bazel build //ic-response-verification-ts:lib
```

## Test in another project

From the root of this repository:

```shell
pushd bazel-bin/ic-response-verification-ts/lib && sudo npm link && popd
```

In your other project:

```shell
npm link @dfinity/response-verification
```
