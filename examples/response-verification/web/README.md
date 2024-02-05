# Web Example Project

This project showcases how to use the `@dfinity/response-verification` package to perform response verification within a frontend web project.

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
pnpm run --filter web-example start
```

## Run with HTTP Server

Bundle application:

```shell
pnpm run --filter web-example build
```

Run:

```shell
pnpm run --filter web-example start:http
```
