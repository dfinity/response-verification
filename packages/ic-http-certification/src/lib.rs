/*!
# HTTP Certification

HTTP certification is a sub-protocol of the [ICP](https://internetcomputer.org/) [HTTP gateway protocol](https://internetcomputer.org/docs/references/http-gateway-protocol-spec). It is used to verify HTTP responses received by an HTTP gateway from a [canister](https://internetcomputer.org/how-it-works/canister-lifecycle/), with respect to the corresponding HTTP request. This allows HTTP gateways to verify that the responses they receive from canisters are authentic and have not been tampered with.

The `ic-http-certification` crate provides the foundation for implementing the HTTP certification protocol in Rust canisters. Certification is implemented in a number of steps:

1. [Defining CEL expressions](#defining-cel-expressions).
2. [Creating certifications](#creating-certifications).
3. [Creating an HTTP certification tree](#creating-an-http-certification-tree).

## Defining CEL expressions

[CEL](https://github.com/google/cel-spec) (Common Expression Language) is a portable expression language that can be used for different applications to easily interoperate. It can be seen as the computation or expression counterpart to [protocol buffers](https://github.com/protocolbuffers/protobuf).

CEL expressions are at the core of ICP's HTTP certification protocol. They are used to define the conditions under which a request and response pair should be certified and also what should be included from the corresponding request and response objects in the certification.

CEL expressions can be created in two ways:
- Using the [CEL builder](#using-the-cel-builder)
- Directly creating a [CEL expression](#directly-creating-a-cel-expression).

### Converting CEL expressions into their `String` representation

Note that the [CelExpression] enum is not a CEL expression itself, but rather a Rust representation of a CEL expression. To convert a [CelExpression] into its [String] representation, use [CelExpression::to_string](ToString::to_string()) or [create_cel_expr](cel::create_cel_expr()). This applies to CEL expressions created both by the [CEL builder](#using-the-cel-builder) and [directly](#directly-creating-a-cel-expression).

```rust
use ic_http_certification::cel::{CelExpression, DefaultCelExpression};

let cel_expr = CelExpression::Default(DefaultCelExpression::Skip).to_string();
```

Alternatively:

```rust
use ic_http_certification::cel::{CelExpression, DefaultCelExpression, create_cel_expr};

let certification = CelExpression::Default(DefaultCelExpression::Skip);
let cel_expr = create_cel_expr(&certification);
```

### Using the CEL builder

The CEL builder interface is provided to ease the creation of CEL expressions through an ergonomic interface. It is also possible to [create CEL expressions directly](#directly-creating-a-cel-expression). To define a CEL expression, start with [DefaultCelBuilder]. This struct provides a set of associated functions that can be used to define how a request and response pair should be certified.

It's possible to
- [Fully certify requests and responses](#fully-certified-request--response-pair).
- [Partially certify requests](#partially-certified-request).
- [Skip request certification](#skipping-request-certification).
- [Partially certify responses](#partially-certified-response).
- [Skip certification entirely](#skipping-certification).

Note that if the request is certified, the response must also be certified. It is not possible to certify a request without also certifying a response. Any combination of fully or partially certified requests and responses can be used.

When a request is certified:

- The request body and method are always certified.
- The request headers and query parameters are optionally certified using the `with_request_headers` and `with_request_query_parameters` associated functions, respectively. Both associated functions take a `str` slice as an argument.

When a response is certified:

- The response body and status code are always certified.
- The response headers are optionally certified using the `with_response_certification` associated function. This function takes the `DefaultResponseCertification` enum as an argument.
  - To specify header inclusions, use the `certified_response_headers` associated function of the `DefaultResponseCertification` enum.
  - To certify all response headers (with some optional  exclusions), use the `response_header_exclusions` associated function of the `DefaultResponseCertification` enum. Both functions take a `str` slice as an argument.

Regardless of what is included in certification, the request path is always used to determine if that certification should be used. It's also possible to set a certification for a "scope" or "directory" of paths; see [Defining tree paths](#defining-tree-paths) for more information on this.

When defining CEL expressions, it's important to determine what should be certified and what can be safely excluded from certification. For example, if a response header is not certified, it will not be included in the certification and will not be verified by the HTTP gateway, meaning that the value of this header cannot be trusted by clients. As a general rule of thumb, starting with a fully certified request and response pair is a good idea and then removing parts of the certification as needed.

It should be considered unsafe to exclude anything from request certification that can change the expected response. The request method, for example, can drastically affect what action is taken by the canister, and so excluding it from certification would allow a malicious replica to respond with the expected responses for a `'GET'` request, even though a `'POST'` request was made.

For responses, it should be considered unsafe to exclude anything from response certification that will be used by clients in a meaningful way. For example, excluding the `Content-Type` header from certification would allow a malicious replica to respond with a different content type than expected, which could cause clients to misinterpret the response.

#### Fully certified request / response pair

To define a fully certified request and response pair, including request headers, query parameters, and response headers use [DefaultCelBuilder::full_certification](DefaultCelBuilder::full_certification()).

For example:

```rust
use ic_http_certification::{DefaultCelBuilder, DefaultResponseCertification};

let cel_expr = DefaultCelBuilder::full_certification()
    .with_request_headers(vec!["Accept", "Accept-Encoding", "If-None-Match"])
    .with_request_query_parameters(vec!["foo", "bar", "baz"])
    .with_response_certification(DefaultResponseCertification::certified_response_headers(vec![
        "Cache-Control",
        "ETag",
    ]))
    .build();
```

#### Partially certified request

Any number of request headers or request query parameters can be certified via `with_request_headers` and `with_request_query_parameters` respectively. Both methods will accept empty arrays, which is the same as not calling them at all. Likewise for `with_request_query_parameters`, if it is called with an empty array or not called at all, then no request query parameters will be certified. If both are called with an empty array, or neither is called, then only the request body and method will be certified, in addition to the response. As a reminder here, the response is always at least partially certified if the request is certified.

For example, to certify only the request body and method, in addition to the response:

```rust
use ic_http_certification::{DefaultCelBuilder, DefaultResponseCertification};

let cel_expr = DefaultCelBuilder::full_certification()
    .with_response_certification(DefaultResponseCertification::certified_response_headers(vec![
        "Cache-Control",
        "ETag",
    ]))
    .build();
```

Alternatively, this can be done more explicitly:

```rust
use ic_http_certification::{DefaultCelBuilder, DefaultResponseCertification};

let cel_expr = DefaultCelBuilder::full_certification()
    .with_request_headers(vec![])
    .with_request_query_parameters(vec![])
    .with_response_certification(DefaultResponseCertification::certified_response_headers(vec![
        "Cache-Control",
        "ETag",
    ]))
    .build();
```

#### Skipping request certification

Request certification can be skipped entirely by using `DefaultCelBuilder::response_only_certification` instead of `DefaultCelBuilder::full_certification`. Request certification should only be skipped if the response is determined solely by the request path. If any other part of the request can affect the response in a meaningful way, then request certification should not be skipped.

For example:

```rust
use ic_http_certification::{DefaultCelBuilder, DefaultResponseCertification};

let cel_expr = DefaultCelBuilder::response_only_certification()
    .with_response_certification(DefaultResponseCertification::response_header_exclusions(vec![
        "Date",
        "Cookie",
        "Set-Cookie",
    ]))
    .build();
```

#### Partially certified response

Any number of response headers can be provided via the `certified_response_headers` associated function of the `DefaultResponseCertification` enum when calling `with_response_certification`. The provided array can also be empty. If the array is empty, or the associated function is not called, no response headers will be certified. If all response headers are to be certified, with some exclusions, use the `response_header_exclusions` associated function of the `DefaultResponseCertification` enum. Care should be taken when choosing what headers to exclude from certification, as they will not be verified by the HTTP gateway. Any headers that hold meaningful information for clients should not be excluded.

For example, to certify only the response body and status code:

```rust
use ic_http_certification::DefaultCelBuilder;

let cel_expr = DefaultCelBuilder::response_only_certification().build();
```


This can also be done more explicitly:

```rust
use ic_http_certification::{DefaultCelBuilder, DefaultResponseCertification};

let cel_expr = DefaultCelBuilder::response_only_certification()
    .with_response_certification(DefaultResponseCertification::certified_response_headers(vec![]))
    .build();
```

The same applies when using [DefaultCelBuilder::response_only_certification](DefaultCelBuilder::response_only_certification()) and [DefaultCelBuilder::full_certification](DefaultCelBuilder::full_certification()).

```rust
use ic_http_certification::DefaultCelBuilder;

let cel_expr = DefaultCelBuilder::full_certification()
    .with_request_headers(vec!["Accept", "Accept-Encoding", "If-None-Match"])
    .with_request_query_parameters(vec!["foo", "bar", "baz"])
    .build();
```

To skip response certification completely, certification overall must be skipped completely. It wouldn't be useful to certify a request without certifying a response.

#### Skipping certification

To skip certification entirely, use [DefaultCelBuilder::skip_certification](DefaultCelBuilder::skip_certification()), for example:

```rust
use ic_http_certification::DefaultCelBuilder;

let cel_expr = DefaultCelBuilder::skip_certification();
```

Skipping certification may seem counterintuitive at first, but it is not always possible to certify a request and response pair. For example, a canister method that will return different data for every user cannot be easily certified.

Typically, these requests have been routed through `raw` ICP URLs in the past, but this is dangerous because `raw` URLs allow any responding replica to decide whether or not certification is required. In contrast, by skipping certification using the above method with a non-`raw` URL, a replica will no longer be able to decide whether or not certification is required and instead this decision will be made by the canister itself and the result will go through consensus.

Extreme caution should be taken when deciding to skip certification entirely. It should only be done when it is not possible to certify a request and response pair, and a modification of the response's content would not pose a security risk for the application.

## Creating certifications

Once a CEL expression has been defined, it can be used in conjunction with an [HttpRequest] and [HttpResponse] to create an instance of the [HttpCertification] struct. The [HttpCertification] struct has three associated functions:

- The [full](HttpCertification::full) associated function is used to include both the [HttpRequest] and the corresponding [HttpResponse] in certification.
- The [response_only](HttpCertification::response_only) associated function is used to include only the [HttpResponse] in certification and exclude the corresponding [HttpRequest] from certification.
- The [skip](HttpCertification::skip) associated function is used to skip certification entirely.

### Full certification

To perform a full certification, a CEL expression created from [DefaultCelBuilder::full_certification] is required, along with an [HttpRequest] and [HttpResponse], and optionally, a pre-calculated response body hash.

For example:

```rust
use ic_http_certification::{HttpCertification, HttpRequest, HttpResponse, DefaultCelBuilder, DefaultResponseCertification, CERTIFICATE_EXPRESSION_HEADER_NAME, StatusCode};

let cel_expr = DefaultCelBuilder::full_certification()
    .with_request_headers(vec!["Accept", "Accept-Encoding", "If-None-Match"])
    .with_request_query_parameters(vec!["foo", "bar", "baz"])
    .with_response_certification(DefaultResponseCertification::certified_response_headers(vec![
        "Cache-Control",
        "ETag",
    ]))
    .build();

let request = HttpRequest::get("/index.html?foo=a&bar=b&baz=c")
    .with_headers(vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("Accept-Encoding".to_string(), "gzip".to_string()),
        ("If-None-Match".to_string(), "987654321".to_string()),
    ])
    .build();

let response = HttpResponse::ok(
  vec![1, 2, 3, 4, 5, 6],
  vec![
    ("Cache-Control".to_string(), "no-cache".to_string()),
    ("ETag".to_string(), "123456789".to_string()),
    (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr.to_string()),
  ]
)
.build();

let certification = HttpCertification::full(&cel_expr, &request, &response, None);
```

### Response-only certification

To perform a response-only certification, a CEL expression created from [DefaultCelBuilder::response_only_certification] is required, along with an [HttpResponse] and, optionally, a pre-calculated response body hash.

For example:

```rust
use ic_http_certification::{HttpCertification, HttpResponse, DefaultCelBuilder, DefaultResponseCertification, CERTIFICATE_EXPRESSION_HEADER_NAME, StatusCode};

let cel_expr = DefaultCelBuilder::response_only_certification()
    .with_response_certification(DefaultResponseCertification::certified_response_headers(vec![
        "Cache-Control",
        "ETag",
    ]))
    .build();

let response = HttpResponse::ok(
  vec![1, 2, 3, 4, 5, 6],
  vec![
    ("Cache-Control".to_string(), "no-cache".to_string()),
    ("ETag".to_string(), "123456789".to_string()),
    (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr.to_string()),
  ]
)
.build();

let certification = HttpCertification::response_only(&cel_expr, &response, None).unwrap();
```

### Skipping certification

Skipping certification does not need an explicit CEL expression to be defined since it's always the same.

For example:

```rust
use ic_http_certification::HttpCertification;

let certification = HttpCertification::skip();
```

## Creating an HTTP certification tree

### Defining tree paths

Paths for the tree can be defined using the [HttpCertificationPath] struct and come in two types - [Wildcard](HttpCertificationPath::wildcard()) and [Exact](HttpCertificationPath::exact()). Both types of paths may end with or without a trailing slash but note that a path ending in a trailing slash is a distinct path from one that does not end with a trailing slash and they will be treated as such by the tree.

Wildcard paths can be used to match a sub-path of a request URL. This can be useful for 404 responses, fallbacks, or rewrites. They are defined using the [Wildcard](HttpCertificationPath::wildcard()) associated function.

In this example, the certification entered into the tree with this path will be valid for any request URL that begins with `/js`, unless there is a more specific path in the tree (e.g., `/js/example.js` or `/js/example`).

```rust
use ic_http_certification::HttpCertificationPath;

let path = HttpCertificationPath::wildcard("/js");
```

Exact paths are used to match an entire request URL. An exact path ending with a trailing slash refers to a file system directory, whereas one without a trailing slash refers to an individual file. Both are separate paths within the certification tree and will be treated completely independently.

In this example, the certification entered into the tree with this path will only be valid for a request URL that is exactly `/js/example.js`.

```rust
use ic_http_certification::HttpCertificationPath;

let path = HttpCertificationPath::exact("/js/example.js");
```

### Using the HTTP certification tree

The [HttpCertificationTree] can be easily initialized with the [Default] trait, and entries can be added to, removed from, or have witnesses generated by the tree using the [HttpCertificationTreeEntry] struct. The [HttpCertificationTreeEntry] requires an [HttpCertification] and an [HttpCertificationPath].

For example:

```rust
use ic_http_certification::{HttpCertification, HttpRequest, HttpResponse, DefaultCelBuilder, DefaultResponseCertification, HttpCertificationTree, HttpCertificationTreeEntry, HttpCertificationPath, CERTIFICATE_EXPRESSION_HEADER_NAME, StatusCode};

let cel_expr = DefaultCelBuilder::full_certification()
    .with_request_headers(vec!["Accept", "Accept-Encoding", "If-None-Match"])
    .with_request_query_parameters(vec!["foo", "bar", "baz"])
    .with_response_certification(DefaultResponseCertification::certified_response_headers(vec![
        "Cache-Control",
        "ETag",
    ]))
    .build();

let request = HttpRequest::get("/index.html?foo=a&bar=b&baz=c")
    .with_headers(vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("Accept-Encoding".to_string(), "gzip".to_string()),
        ("If-None-Match".to_string(), "987654321".to_string()),
    ])
    .build();

let response = HttpResponse::ok(
  vec![1, 2, 3, 4, 5, 6],
  vec![
    ("Cache-Control".to_string(), "no-cache".to_string()),
    ("ETag".to_string(), "123456789".to_string()),
    (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr.to_string()),
  ]
)
.build();

let request_url = "/example.json";
let path = HttpCertificationPath::exact(request_url);
let certification = HttpCertification::full(&cel_expr, &request, &response, None).unwrap();

let mut http_certification_tree = HttpCertificationTree::default();

let entry = HttpCertificationTreeEntry::new(&path, &certification);

// insert the entry into the tree
http_certification_tree.insert(&entry);

// generate a witness for this entry in the tree
let witness = http_certification_tree.witness(&entry, request_url);

// delete the entry from the tree
http_certification_tree.delete(&entry);
```

### Handling upgrades

CEL expressions, certifications, the certification tree, and the corresponding requests and responses are not persisted across upgrades, by default. This means that if a canister is upgraded, all of this information will be lost. To handle upgrades effectively, all initialization logic run in the canister's `init` hook should also be run in the `post_upgrade` hook. This will ensure that the certification tree is correctly re-initialized after an upgrade. Most data structures, aside from the certification tree, can be persisted using stable memory, and the certification tree can be re-initialized using this persisted data. Care should be taken to not exceed the canister's instruction limit when re-initializing the certification tree, which can easily occur if the number of responses being certified grows very large. This case could potentially be addressed in the future by developing a stable memory-compatible certification tree.

### Changing data

In addition to initializing certifications in the `init` and `post_upgrade` hooks, if a response is changed during the canister's lifetime in response to an `update` call, the certification tree should be updated to reflect this change. This can be done by deleting the old certification from the tree and inserting the new certification. This should be done in the same `update` call as the response is changed to ensure that the certification tree is always up-to-date; otherwise, `query` calls returning that response will fail verification.

## Directly creating a CEL expression

To define a CEL expression, start with the [CelExpression] enum. This enum provides a set of variants that can be used to define different types of CEL expressions supported by ICP HTTP gateways. Currently only one variant is supported, known as the "default" certification expression, but more may be added in the future as the HTTP certification protocol evolves over time.

When certifying requests:

- The request body and method are always certified.
- To certify request headers and query parameters, use the [headers](cel::DefaultRequestCertification::headers) and [query_parameters](cel::DefaultRequestCertification::query_parameters) fields of the [DefaultRequestCertification](cel::DefaultRequestCertification) struct. Both fields take a [str] slice as an argument.

When certifying responses:

- The response body and status code are always certified.
- To certify response headers, use the [certified_response_headers](DefaultResponseCertification::certified_response_headers) associated function of the [DefaultResponseCertification] enum. Or to certify all response headers, with some exclusions, use the [response_header_exclusions](DefaultResponseCertification::response_header_exclusions) associated function of the [DefaultResponseCertification] enum. Both associated functions take a [str] slice as an argument.

Note that the example CEL expressions provided below are formatted for readability. The actual CEL expressions produced by [CelExpression::to_string](ToString::to_string()) and [create_cel_expr](cel::create_cel_expr()) are minified. The minified CEL expression is preferred because it is more compact, resulting in a smaller payload and a faster evaluation time for the HTTP Gateway that is verifying the certification, but the formatted versions are also accepted.

### Fully certified request / response pair

To define a fully certified request and response pair, including request headers, query parameters, and response headers:

```rust
use std::borrow::Cow;
use ic_http_certification::cel::{CelExpression, DefaultCelExpression, DefaultFullCelExpression, DefaultRequestCertification, DefaultResponseCertification};

let cel_expr = CelExpression::Default(DefaultCelExpression::Full(
  DefaultFullCelExpression {
    request: DefaultRequestCertification::new(
      vec!["Accept", "Accept-Encoding", "If-None-Match"],
      vec!["foo", "bar", "baz"],
    ),
    response: DefaultResponseCertification::certified_response_headers(vec![
      "ETag",
      "Cache-Control",
    ]),
  }));
```

This will produce the following CEL expression:

```protobuf
default_certification (
  ValidationArgs {
    request_certification: RequestCertification {
      certified_request_headers: ["Accept", "Accept-Encoding", "If-None-Match"],
      certified_query_parameters: ["foo", "bar", "baz"]
    },
    response_certification: ResponseCertification {
      certified_response_headers: ResponseHeaderList {
        headers: [
          "ETag",
          "Cache-Control"
        ]
      }
    }
  }
)
```

### Partially certified request

Any number of request headers or query parameters can be provided via the [headers](cel::DefaultRequestCertification::headers) and [query_parameters](cel::DefaultRequestCertification::query_parameters) fields of the [DefaultRequestCertification](cel::DefaultRequestCertification) struct, and both can be an empty array. If the [headers](cel::DefaultRequestCertification::headers) field is empty, no request headers will be certified. Likewise for the [query_parameters](cel::DefaultRequestCertification::query_parameters) field, if it is empty, then no query parameters will be certified. If both are empty, only the request body and method will be certified.

For example, to certify only the request body and method:

```rust
use std::borrow::Cow;
use ic_http_certification::cel::{CelExpression, DefaultCelExpression, DefaultFullCelExpression, DefaultRequestCertification, DefaultResponseCertification};

let cel_expr = CelExpression::Default(DefaultCelExpression::Full(
  DefaultFullCelExpression {
    request: DefaultRequestCertification::new(
      vec![],
      vec![],
    ),
    response: DefaultResponseCertification::certified_response_headers(vec![
      "ETag",
      "Cache-Control",
    ]),
  }));
```

This will produce the following CEL expression:

```protobuf
default_certification (
  ValidationArgs {
    request_certification: RequestCertification {
      certified_request_headers: [],
      certified_query_parameters: []
    },
    response_certification: ResponseCertification {
      certified_response_headers: ResponseHeaderList {
        headers: [
          "ETag",
          "Cache-Control"
        ]
      }
    }
  }
)
```

### Skipping request certification

Request certification can be skipped entirely by using the [ResponseOnly](DefaultCelExpression::ResponseOnly) variant of the [DefaultCelExpression].

For example:

```rust
use std::borrow::Cow;
use ic_http_certification::cel::{CelExpression, DefaultCelExpression, DefaultResponseOnlyCelExpression, DefaultResponseCertification};

let cel_expr = CelExpression::Default(DefaultCelExpression::ResponseOnly(
  DefaultResponseOnlyCelExpression {
    response: DefaultResponseCertification::certified_response_headers(vec![
      "ETag",
      "Cache-Control",
    ]),
  }));
```

This will produce the following CEL expression:

```protobuf
default_certification (
  ValidationArgs {
    no_request_certification: Empty {},
    response_certification: ResponseCertification {
      certified_response_headers: ResponseHeaderList {
        headers: [
          "ETag",
          "Cache-Control"
        ]
      }
    }
  }
)
```

### Partially certified response

Similarly to request certification, any number of response headers can be provided via the [certified_response_headers](DefaultResponseCertification::certified_response_headers) associated function of the [DefaultResponseCertification] enum, and it can also be an empty array. If the array is empty, no response headers will be certified.

For example:

```rust
use std::borrow::Cow;
use ic_http_certification::cel::{CelExpression, DefaultCelExpression, DefaultFullCelExpression, DefaultRequestCertification, DefaultResponseCertification};


let cel_expr = CelExpression::Default(DefaultCelExpression::Full(
  DefaultFullCelExpression {
    request: DefaultRequestCertification::new(
      vec!["Accept", "Accept-Encoding", "If-None-Match"],
      vec!["foo", "bar", "baz"],
    ),
    response: DefaultResponseCertification::certified_response_headers(vec![]),
  }));
```

This will produce the following CEL expression:

```protobuf
default_certification (
  ValidationArgs {
    request_certification: RequestCertification {
      certified_request_headers: ["Accept", "Accept-Encoding", "If-None-Match"],
      certified_query_parameters: ["foo", "bar", "baz"]
    },
    response_certification: ResponseCertification {
      certified_response_headers: ResponseHeaderList {
        headers: []
      }
    }
  }
)
```

If the [response_header_exclusions](DefaultResponseCertification::response_header_exclusions) associated function is used, an empty array will certify _all_ response headers. For example:

```rust
use std::borrow::Cow;
use ic_http_certification::cel::{CelExpression, DefaultCelExpression, DefaultFullCelExpression, DefaultRequestCertification, DefaultResponseCertification};

let cel_expr = CelExpression::Default(DefaultCelExpression::Full(
  DefaultFullCelExpression {
    request: DefaultRequestCertification::new(
      vec!["Accept", "Accept-Encoding", "If-None-Match"],
      vec!["foo", "bar", "baz"],
    ),
    response: DefaultResponseCertification::response_header_exclusions(vec![]),
  }));
```

This will produce the following CEL expression:

```protobuf
default_certification (
  ValidationArgs {
    request_certification: RequestCertification {
      certified_request_headers: ["Accept", "Accept-Encoding", "If-None-Match"],
      certified_query_parameters: ["foo", "bar", "baz"]
    },
    response_certification: ResponseCertification {
      response_header_exclusions: ResponseHeaderList {
        headers: []
      }
    }
  }
)
```

To skip response certification completely, then certification overall must be skipped completely. It wouldn't be useful to certify a request without certifying a response.

### Skipping certification

To skip certification entirely:

```rust
use ic_http_certification::cel::{CelExpression, DefaultCelExpression};

let cel_expr = CelExpression::Default(DefaultCelExpression::Skip);
```

This will produce the following CEL expression:

```protobuf
default_certification (
  ValidationArgs {
    no_certification: Empty {}
  }
)
```
*/

#![deny(missing_docs, missing_debug_implementations, rustdoc::all, clippy::all)]

pub mod cel;
pub use cel::{
    CelExpression, DefaultCelBuilder, DefaultCelExpression, DefaultFullCelExpression,
    DefaultResponseCertification, DefaultResponseOnlyCelExpression,
};
pub mod hash;
pub use hash::*;
pub mod error;
pub use error::*;
pub mod http;
pub use http::*;
pub mod tree;
pub use tree::*;
pub mod utils;

// https://github.com/la10736/rstest/tree/master/rstest_reuse#cavelets
#[cfg(test)]
#[allow(clippy::single_component_path_imports)]
use rstest_reuse;
