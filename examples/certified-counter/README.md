# Certified Counter

This example project demonstrates how to create a certification for non-replicated query call responses from a simple counter canister and verify that certification client side.

## Running the project locally

From the root of repository, install pnpm dependencies:

```shell
pnpm i
```

Build the `@dfinity/certificate-verification` package:

```shell
pnpm run --filter @dfinity/certificate-verification build
```

Now change to this project's directory:

```shell
cd examples/certified-counter
```

Run DFX:

```shell
dfx start --background
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
