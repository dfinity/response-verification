# Response Verification

## Usage

### In the browser

Before executing any functions, the library needs to be initialized using the default import.

```typescript
import initResponseVerification, {
  sayHello,
} from '@dfinity/response-verification';

window.addEventListener('load', async () => {
  await initResponseVerification();

  console.log(sayHello());
});
```

## Examples

- [NodeJS](./examples/nodejs/README.md)
- [Rust](./examples/rust/README.md)
- [Service Worker](./examples/service-worker/README.md)
- [Web](./examples/web/README.md)

## Developer Documentation

### Setup

- [Install pre-commit](https://pre-commit.com/#installation)
- [Install commitizen](https://commitizen-tools.github.io/commitizen/#installation)

### Making a Commit

```shell
cz commit
```

See [Conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) for more information on the commit message formats

### Sub Projects

- [Response Verification Rust Crate](./ic-response-verification-rs/README.md)
- [Response Verification NPM Package](./ic-response-verification-ts/README.md)
