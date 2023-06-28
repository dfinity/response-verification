# Response Verification

## Overview

Response verification on the [Internet Computer](https://dfinity.org) is the process of verifying that a canister response from a replica has gone through consensus with other replicas hosting the same canister.

This package encapsulates the protocol for such verification. It is used by [the Service Worker](https://github.com/dfinity/ic/tree/master/typescript/service-worker) and [ICX Proxy](https://github.com/dfinity/ic/tree/master/rs/boundary_node/icx_proxy) and may be used by other implementations of the [HTTP Gateway Protocol](https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway) in the future.

## Examples

- [NodeJS](./examples/nodejs/README.md)
- [Rust](./examples/rust/README.md)
- [Service Worker](./examples/service-worker/README.md)
- [Web](./examples/web/README.md)
- [Certified Counter](./examples/certified-counter/README.md)

## Contributing

Check out our [contribution guidelines](./.github/CONTRIBUTING.md).

### Setup

- [Install pre-commit](https://pre-commit.com/#installation)
- [Install commitizen](https://commitizen-tools.github.io/commitizen/#installation)
- [Install Rust](https://www.rust-lang.org/learn/get-started)
- [Install wasm-pack](https://rustwasm.github.io/wasm-pack/installer)
- [Install NodeJS](https://nodejs.org/en/download/)
- [Install pnpm](https://pnpm.io/installation)
- [Install DFX](https://internetcomputer.org/docs/current/developer-docs/setup/install)

### Making a Commit

```shell
cz commit
```

See [Conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) for more information on the commit message formats

### Sub Projects

#### Response Verification

- [Rust Crate](./packages/ic-response-verification/README.md)
- [NPM Package](./packages/ic-response-verification-wasm/README.md)
- [e2e Tests](./packages/ic-response-verification-tests/README.md)

#### Certificate Verification

- [NPM Package](./packages/certificate-verification-js/README.md)

#### Miscellaneous

- [Representation Independent Hash Rust Crate](./packages/ic-representation-independent-hash/README.md)

## Commands

| Project                             | Command                                                     | Description                    |
| ----------------------------------- | ----------------------------------------------------------- | ------------------------------ |
| All                                 | `pnpm build`                                                | Build all NPM projects         |
| `@dfinity/certification-test-utils` | `pnpm run --filter @dfinity/certification-test-utils build` | Build certification test utils |
| `@dfinity/response-verification` | `pnpm run --filter @dfinity/response-verification build` | Build the response verification JS library |
