# Web Example Project

## Setup

From the root of this repository,
Build the `@dfinity/response-verification` package:

```shell
./scripts/package.sh
```

Link `@dfinity/response-verification` globally:

```shell
pushd ./pkg && sudo npm link && popd
```

Change into this project's directory:

```
cd examples/web
```

Install NPM modules:

```shell
npm install
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
