# Certified Counter

This example project demonstrates how to create a certification for non-replicated query call responses from a simple counter canister and verify that certification client side.

## Running the project locally

From this project's directory:

```shell
cd examples/certification/certified-counter
```

Start DFX:

```shell
dfx start --background
```

Create canisters:

```shell
dfx canister create --all
```

Generate backend canister bindings:

```shell
dfx generate backend
```

Back to the root of repository:

```shell
cd ../../
```

Install pnpm dependencies:

```shell
pnpm i
```

Build the `@dfinity/certificate-verification` package:

```shell
pnpm run --filter @dfinity/certificate-verification build
```

Now change to this project's directory again:

```shell
cd examples/certification/certified-counter
```

Build and deploy the canisters:

```shell
dfx deploy
```

Print the web URL of the canister:

```shell
echo "http://$(dfx canister id frontend).localhost:$(dfx info webserver-port)"
```

Now you can open that URL in your web browser.
