# Contributing

Thank you for your interest in contributing to the Response Verification package for the Internet Computer.
By participating in this project, you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

As a member of the community, you are invited and encouraged to contribute by submitting issues, offering suggestions for improvements, adding review comments to existing pull requests, or creating new pull requests to fix issues.

All contributions to DFINITY documentation and the developer community are respected and appreciated.
Your participation is an important factor in the success of the Internet Computer.

## Prerequisites

Before contributing, please take a few minutes to review these contributor guidelines.
The contributor guidelines are intended to make the contribution process easy and effective for everyone involved in addressing your issue, assessing changes, and finalizing your pull requests.

Before contributing, consider the following:

- If you want to report an issue, click [issues](https://github.com/dfinity/response-verification/issues).
- If you have more general questions related to this package and its use, post a message to the [community forum](https://forum.dfinity.org/).
- If you are reporting a bug, provide as much information about the problem as possible.
- If you want to contribute directly to this repository, typical fixes might include any of the following:
  - Fixes to resolve bugs or documentation errors
  - Code improvements
  - Feature requests
  - Note that any contribution to this repository must be submitted in the form of a **pull request**.
- If you are creating a pull request, be sure that the pull request only implements one fix or suggestion.

If you are new to working with GitHub repositories and creating pull requests, consider exploring [First Contributions](https://github.com/firstcontributions/first-contributions) or [How to Contribute to an Open Source Project on GitHub](https://egghead.io/courses/how-to-contribute-to-an-open-source-project-on-github).

## Reporting an issue

To open a new issue:

1. Click [create a new issue](https://github.com/dfinity/response-verification/issues/new).
2. Type a title and description, then click **Submit new issue**.
   - Be as clear and descriptive as possible.
   - For any problem, describe it in detail, including details about the crate, the version of the code you are using, the results you expected, and how the actual results differed from your expectations.

## Submitting a pull request

If you want to submit a pull request to fix an issue or add a feature, here's a summary of what you need to do:

### Forking the repository

1. Make sure you have a GitHub account, an internet connection, and access to a terminal shell or GitHub Desktop application for running commands.
2. Navigate to the [repository's homepage](https://github.com/dfinity/response-verification) in a web browser.
3. Click **Fork** to create a copy of the repository under your GitHub account or organization name.
4. Clone the forked repository to your local machine.
   ```shell
   git clone "https://github.com/$YOUR_USERNAME/response-verification.git"
   ```
5. Change into the directory of the cloned repository:
   ```shell
   cd response-verification
   ```
6. Create a new branch for your fix by running a command similar to the
   following:
   ```shell
   git checkout -b $YOUR_BRANCH_NAME
   ```

### Making a pull request

1. Open the file you want to fix in a text editor and make the appropriate
   changes for the issue you are trying to address.
2. Add the file contents of the changed files to the index `git` uses to manage
   the state of the project by running a command similar to the following:
   ```shell
   git add $PATH_TO_CHANGED_FILE
   ```
3. Make sure to have
   [Commitizen](https://commitizen-tools.github.io/commitizen/#installation)
   installed.
4. Commit your changes to store the contents you added to the index along with a
   descriptive message by running the following:
   ```shell
   cz commit
   ```
5. Push the changes to the remote repository by running a command similar to the following:
   ```shell
   git push origin $YOUR_BRANCH_NAME
   ```
6. Create a new pull request (PR) for the branch you pushed to the upstream GitHub repository.
   - The PR title should be auto-populated based on your commit message.
   - Provide a PR message that includes a short description of the changes made.
7. Wait for the pull request to be reviewed.
8. Make changes to the pull request, if requested. When making subsequent commits, you no longer need to follow conventional commits. Only the first commit message will be used.
9. Celebrate your success after your pull request is merged!

## System Setup

- [Install pre-commit](https://pre-commit.com/#installation)
- [Install commitizen](https://commitizen-tools.github.io/commitizen/#installation)
- [Install Rust](https://www.rust-lang.org/learn/get-started)
- [Install wasm-pack](https://rustwasm.github.io/wasm-pack/installer)
- [Install fnm](https://github.com/Schniz/fnm)
- [Install dfx](https://internetcomputer.org/docs/building-apps/getting-started/install)

Install the correct version of NodeJS:

```shell
fnm install
```

Activate the correct version of NodeJS:

```shell
fnm use
```

Install and activate the correct version of PNPM:

```shell
corepack enable
```

Install PNPM dependencies:

```shell
pnpm i
```

## Command Reference

Make sure to follow the [system setup](#system-setup) instructions first.

| Command       | Description             |
| ------------- | ----------------------- |
| `cargo build` | Build all Cargo crates  |
| `cargo test`  | Test all Cargo crates   |
| `cargo fmt`   | Format all Cargo crates |
| `pnpm build`  | Build all NPM packages  |
| `pnpm test`   | Test all NPM packages   |
| `pnpm format` | Format all NPM packages |

### Certification

| Command                                          | Description            |
| ------------------------------------------------ | ---------------------- |
| `cargo build -p ic-certification`                | Build Cargo crate      |
| `cargo test -p ic-certification`                 | Test Cargo crate       |
| `cargo doc -p ic-certification --no-deps --open` | Build Cargo crate docs |

### Certificate Verification

| Command                                               | Description       |
| ----------------------------------------------------- | ----------------- |
| `pnpm run -F @dfinity/certificate-verification build` | Build NPM package |
| `pnpm run -F @dfinity/certificate-verification test`  | Test NPM package  |

### Certification Testing

| Command                                                  | Description            |
| -------------------------------------------------------- | ---------------------- |
| `cargo build -p ic-certification-testing`                | Build Cargo crate      |
| `cargo doc -p ic-certification-testing --no-deps --open` | Build Cargo crate docs |
| `pnpm run -F @dfinity/certification-testing build`       | Build NPM package      |

### HTTP Certification

| Command                                               | Description            |
| ----------------------------------------------------- | ---------------------- |
| `cargo build -p ic-http-certification`                | Build Cargo crate      |
| `cargo test -p ic-http-certification`                 | Test Cargo crate       |
| `cargo doc -p ic-http-certification --no-deps --open` | Build Cargo crate docs |

### Asset Certification

| Command                                                | Description            |
| ------------------------------------------------------ | ---------------------- |
| `cargo build -p ic-asset-certification`                | Build Cargo crate      |
| `cargo test -p ic-asset-certification`                 | Test Cargo crate       |
| `cargo doc -p ic-asset-certification --no-deps --open` | Build Cargo crate docs |

### Response Verification

| Command                                                                 | Description            |
| ----------------------------------------------------------------------- | ---------------------- |
| `cargo build -p ic-response-verification`                               | Build Cargo crate      |
| `cargo test -p ic-response-verification`                                | Test Cargo crate       |
| `wasm-pack test --node packages/ic-response-verification --features=js` | Test Cargo crate WASM  |
| `cargo doc -p ic-response-verification --no-deps --open`                | Build Cargo crate docs |
| `pnpm run -F @dfinity/response-verification build`                      | Build NPM package      |
| `pnpm run -F @dfinity/response-verification test`                       | Test NPM package       |
| `./scripts/e2e.sh`                                                      | Run e2e tests          |

### Representation Independent Hash

| Command                                                            | Description            |
| ------------------------------------------------------------------ | ---------------------- |
| `cargo build -p ic-representation-independent-hash`                | Build Cargo crate      |
| `cargo test -p ic-representation-independent-hash`                 | Test Cargo crate       |
| `cargo doc -p ic-representation-independent-hash --no-deps --open` | Build Cargo crate docs |

### CBOR

| Command                                 | Description            |
| --------------------------------------- | ---------------------- |
| `cargo build -p ic-cbor`                | Build Cargo crate      |
| `cargo test -p ic-cbor`                 | Test Cargo crate       |
| `cargo doc -p ic-cbor --no-deps --open` | Build Cargo crate docs |

### Working on WASM crates

Until Cargo supports [per package targets](https://github.com/rust-lang/cargo/issues/9406), the WASM crates are excluded from the `default_members` array of the Cargo workspace.
Commands such as `cargo build` and `cargo check` will not include these crates, so they must be built separately with the corresponding `pnpm` command listed under [projects](#projects).

Since `rust-analyzer` will also apply the same target to all crates, these crates will show errors in the IDE. To workaround this, create a `.cargo/config.toml` file:

```toml
[build]
target = "wasm32-unknown-unknown"
```

While this file exists, some of the non-WASM crates will show errors instead. Delete the file to work on the non-WASM crates.

### Adding a new package

- Follow the [Package naming conventions](#package-naming-conventions) when naming the package.
- Add the package's package manager file to the `version_files` field in `.cz.yaml`.
  - `package.json` for NPM packages
  - Nothing for for Cargo crates, it is already covered by the root `Cargo.toml`
- Set the initial version of the package in its package manager file to match the current version in the `version` field in `.cz.yaml`
  - For `package.json`, set the version manually
  - For `Cargo.toml`, use `version.workspace = true`
- Add the package's package manager file(s) to the `add-paths` property in the `Create Pull Request` job of the `Create Release PR` workflow in `.github/workflows/create-release-pr.yml`
  - `package.json` for NPM packages
  - No files need to be added for Cargo crates
- If the package is a Rust crate:
  - Add the package to the `members` section in `Cargo.toml` and the `default-members` section
    - If the package must be compiled to WASM then do not add it to the `default-members` section
  - Add a `Release ic-<package-name> Cargo crate` job to the `Release` workflow in `.github/workflows/release.yml`
  - Add `target/package/ic-<package-name>-${{ github.ref_name }}.crate` to the `artifacts` property in the `Create Github release` job of the `Release` workflow in `.github/workflows/release.yml`
    - Make sure every entry except the last is comma delimited
  - If the crate has dependenencies in this repository, make sure it is published _after_ the dependencies
  - If the crate has a dependent in this repository, make sure it is published _before_ the dependents
- If the package is an NPM package:
  - Add the package to `pnpm-workspace.yaml`
  - Add a `Pack @dfinity/<package-name> NPM package` job to the `Release` workflow in `.github/workflows/release.yml`
  - Add a `Release @dfinity/<package-name> NPM package` job to the `Release` workflow in `.github/workflows/release.yml`
  - Add `dfinity-<package-name>-${{ github.ref_name }}.tgz` to the `artifacts` property in the `Create Github release` job of the `Create Release PR` workflow in `.github/workflows/create-release-pr.yml`
    - Make sure every entry except the last is comma delimited

### Package naming conventions

Cargo crates are named `ic-<package-name>`, likewise for the folder name.
If the Cargo crate will be compiled to WASM then the folder name is `ic-<package-name>-wasm`.

NPM packages are named `@dfinity/<package-name>`.
If the NPM package is a pure JS package then the folder name is `<package-name>-js`.
If the NPM package is built from a Rust crate then the folder name is `ic-<package-name>-wasm`.

### Referencing a Cargo crate

A Cargo crate can be referenced using a relative path in `Cargo.toml`:

```toml
[dependencies]
ic-response-verification-test-utils = { path = "../ic-response-verification-test-utils" }
```

If the _referencing_ Cargo crate is published to crates.io then the current version must be included and the _referenced_ crate must also be published:

```toml
[dependencies]
ic-response-verification-test-utils = { path = "../ic-response-verification-test-utils", version = "1.0.0" }
```

If a version is included in a dev dependency then the referenced dev dependency must also be published, but the version can be omitted for dev dependencies to avoid this.

### Referencing an NPM package

An NPM package can be referenced using the package name and [PNPM workspace protocol](https://pnpm.io/workspaces#workspace-protocol-workspace) in `package.json`:

```json
{
  "dependencies": {
    "@dfinity/certificate-verification": "workspace:*"
  }
}
```
