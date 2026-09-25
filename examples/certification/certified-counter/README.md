# Certified Counter

This example project demonstrates how to create a certification for non-replicated query call responses from a simple counter canister and verify that certification client side.

## Running the project locally

Run these commands from the root of the repository, with [icp-cli](https://cli.internetcomputer.org/1.5/guides/installation/) installed.

Install pnpm dependencies:

```shell
pnpm i
```

Generate the backend canister's Candid declarations:

```shell
pnpm run generate
```

Build the `@dfinity/certificate-verification` package:

```shell
pnpm run --filter @dfinity/certificate-verification build
```

Start a local network:

```shell
icp network start -d
```

Build and deploy the canisters:

```shell
icp deploy certification_certified_counter_backend certification_certified_counter_frontend
```

`icp deploy` prints the frontend's URL, `http://certification_certified_counter_frontend.local.localhost:8000/`. Open it in your web browser.

The frontend reads the backend's canister ID and the local network's root key from the `ic_env` cookie that the frontend canister sets, so it never fetches the root key at runtime.
