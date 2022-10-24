# Response Verification NPM Package

## Dependencies

To install Cargo binary dependencies, run the following:
```shell
bazel run //3rdparty:crates_vendor
```

If the binary dependencies (in the 3rdparty folder) have changed, run the following:
```shell
CARGO_BAZEL_REPIN=true bazel run //3rdparty:crates_vendor
```

## Build

```shell
$ bazel build //ic-response-verification-ts:lib
```

## Test in another project

From the root of this repository:

```shell
$ pushd bazel-bin/ic-response-verification-ts/lib && sudo npm link && popd
```

In your other project:

```shell
$ npm link @dfinity/response-verification
```
