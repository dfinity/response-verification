# Service Worker Example Project

## Gotchas

When bundling a service worker with Webpack, the target needs to be set to `webworker`. Otherwise Webpack will transform the `import.meta.url` line from `wasm-bindgen` into `document.location.href`, which will break in a service worker context.

## Setup

Install NPM modules:

```shell
$ npm install
```

Build the `@dfinity/response-verification` package:

```shell
$ bazel build //ic-response-verification-ts:lib
```

Link `@dfinity/response-verification` globally:

```shell
$ pushd ../../bazel-bin/ic-response-verification-ts/lib && sudo npm link && popd
```

Link `@dfinity/response-verification` in this project:

```shell
$ npm link @dfinity/response-verification
```

## Run with Webpack Dev Server

Run:

```shell
$ npm start
```

## Run with HTTP Server

Bundle application:

```shell
$ npm run build
```

Run:

```shell
$ npm run start:http
```
