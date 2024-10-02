# Skipping certification for HTTP responses

## Overview

This guide walks through an example project that demonstrates how to skip HTTP certification for all possible responses from a canister.

WARNING!!! This means that a malicious replica can return whatever data it wants in response to requests directed towards the canister. Think carefully about whether or not this is the right fit for the canister. If certification should only be skipped for certain paths, then check out the ["Serving static assets over HTTP"](https://internetcomputer.org/docs/current/developer-docs/web-apps/http-compatible-canisters/serving-static-assets-over-http) guide where this approach is covered in more detail.

This is not a beginner's canister development guide. Many foundational concepts that a relatively experienced canister developer should already know will be omitted. Concepts specific to HTTP Certification will be called out here and can help to understand the [full code example](https://github.com/dfinity/response-verification/tree/main/examples/http-certification/skip-certification).

## Prerequisites

This is a relatively simple guide so there's no prerequisites as such, but it's recommended to check out the full certification guides to make sure that certification is not a good fit for your project.

- [x] Complete the ["Serving static assets over HTTP"](https://internetcomputer.org/docs/current/developer-docs/web-apps/http-compatible-canisters/serving-static-assets-over-http) guide.
- [x] Complete the ["Custom HTTP Canisters"](https://internetcomputer.org/docs/current/developer-docs/http-compatible-canisters/custom-http-canisters) guide.
- [x] Complete the ["Serving JSON over HTTP"](https://internetcomputer.org/docs/current/developer-docs/http-compatible-canisters/serving-json-over-http) guide.

# Skipping certification

Skipping certification for all responses is a relatively simple task that can be completed in 2 steps.

First, set the canister's certified data in the canister's `init` lifecycle hook:

```rust
use ic_cdk::*;
use ic_http_certification::utils::skip_certification_certified_data;

#[init]
fn init() {
    set_certified_data(&skip_certification_certified_data());
}
```

This will make sure that the correct certified data is set so that it can be signed during the next consensus round.

Next, when responding to HTTP requests, add the certificate header that will instruct the HTTP Gateway to skip verification:

```rust
use ic_cdk::{api::data_certificate, *};
use ic_http_certification::utils::add_skip_certification_header;

#[query]
fn http_request() -> HttpResponse<'static> {
    let mut response = create_response();

    add_skip_certification_header(data_certificate().unwrap(), &mut response);

    response
}
```

The call to `data_certificate` returns a certificate that proves the canister's certified data was signed by consensus. This will be included in the header along with all additional information required by the HTTP Gateway to safely skip verification of this response.

# Testing out the canister

Start DFX:

```shell
dfx start --background
```

Deploy the canister:

```shell
dfx deploy
```

Make a request to the canister using cURL:

```shell
curl http://localhost:$(dfx info webserver-port)?canisterId=$(dfx canister id backend)
```

You should see output similar to the following:

```html
<html>
  <head>
    <title>IC Skip Certification</title>
  </head>

  <body>
    <h1>IC Skip Certification</h1>
    <p>This is an example of an IC canister that skips certification.</p>
    <p>Current timestamp: 1725546616552162368<b>
  </body>
</html>
```

Alternatively, print the URL in the terminal and then open in a browser:

```shell
echo http://localhost:$(dfx info webserver-port)?canisterId=$(dfx canister id backend)
```

## Resources

- [Example source code](https://github.com/dfinity/response-verification/tree/main/examples/http-certification/skip-certification).
- [`ic-http-certification` crate](https://crates.io/crates/ic-http-certification).
- [`ic-http-certification` docs](https://docs.rs/ic-http-certification/latest/ic_http_certification).
- [`ic-http-certification` source code](https://github.com/dfinity/response-verification/tree/main/packages/ic-http-certification).
