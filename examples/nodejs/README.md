# NodeJS Example Project

## Setup

Install NPM modules:

```shell
npm install
```

Build the `@dfinity/response-verification` package:

```shell
bazel build //packages/ic-response-verification-wasm:lib
```

Link `@dfinity/response-verification` globally:

```shell
pushd ../../bazel-bin/packages/ic-response-verification-wasm/lib && sudo npm link && popd
```

Link `@dfinity/response-verification` in this project:

```shell
npm link @dfinity/response-verification
```

## Run with TSNode

Run:

```shell
npm start
```

## Run with Node

Compile TypeScript:

```shell
npm run build
```

Run:

```shell
node ./dist/index.js
```
