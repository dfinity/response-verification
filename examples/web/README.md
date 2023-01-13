# Web Example Project

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

## Run with Webpack Dev Server

Run:

```shell
npm start
```

## Run with HTTP Server

Bundle application:

```shell
npm run build
```

Run:

```shell
npm run start:http
```
