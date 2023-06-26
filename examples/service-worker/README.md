# Service Worker Example Project

This project showcases how to use the `@dfinity/response-verification` package to perform response verification within a service worker. Also see the [Dfinity service worker](https://github.com/dfinity/ic/tree/master/typescript/service-worker) for a full working example.

## Gotchas

When bundling a service worker with Webpack, the target needs to be set to `webworker`. Otherwise Webpack will transform the `import.meta.url` line from `wasm-bindgen` into `document.location.href`, which will break in a service worker context.

## Setup

From the root of this repository, install NPM dependencies:

```shell
pnpm i
```

Build the `@dfinity/response-verification` package:

```shell
pnpm run --filter @dfinity/response-verification build
```

## Run with Webpack Dev Server

Run:

```shell
pnpm run --filter service-worker-example start
```

## Run with HTTP Server

Bundle application:

```shell
pnpm run --filter service-worker-example build
```

Run:

```shell
pnpm run --filter service-worker-example start:http
```
