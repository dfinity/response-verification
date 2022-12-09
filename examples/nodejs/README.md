# NodeJS Example Project

## Setup

Install NPM modules:

```shell
npm install
```

Build the `@dfinity/response-verification` package:

```shell
bazel build //ic-response-verification-ts:lib
```

Link `@dfinity/response-verification` globally:

```shell
pushd ../../bazel-bin/ic-response-verification-ts/lib && sudo npm link && popd
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
