# Asset Certification

## Overview

Asset certification is a specialized form of
[HTTP Certification](https://internetcomputer.org/docs/current/developer-docs/http-compatible-canisters/custom-http-canisters)
purpose-built for certifying static assets in [ICP](https://internetcomputer.org/) canisters.

The `ic-asset-certification` crate provides the necessary functionality to
certify and serve static assets from Rust canisters.

This is implemented in the following steps:

1. [Preparing assets](#preparing-assets)
2. [Configuring asset certification](#configuring-asset-certification)
3. [Inserting assets into the asset router](#inserting-assets-into-the-asset-router)
4. [Serving assets](#serving-assets)

## Preparing assets

This library is unopinionated about where assets come from, so that is not
covered in detail here, but there are three main options:

- Embedding assets in the canister at compile time:
  - [include_bytes!](https://doc.rust-lang.org/std/macro.include_bytes.html)
  - [include_dir!](https://docs.rs/include_dir/latest/include_dir/index.html)
- Uploading assets via canister endpoints at runtime.
  - The [DFX asset canister](https://github.com/dfinity/sdk/blob/master/docs/design/asset-canister-interface.md) is a good example of this approach.
- Generating assets dynamically in code, at runtime.

With the assets in memory, they can be converted into the `Asset` type:

```rust
use ic_asset_certification::Asset;

let asset = Asset::new(
    "index.html",
    b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
);
```

It is recommended to use references when including assets directly into the
canister, to avoid duplicating the content. This is particularly important for
larger assets.

```rust
use ic_asset_certification::Asset;

let pretty_big_asset = include_bytes!("lib.rs");
let asset = Asset::new(
    "assets/pretty-big-asset.gz",
    pretty_big_asset.as_slice(),
);
```

In some cases, it may be necessary to use owned values, such as when assets are
dynamically generated or modified at runtime.

```rust
use ic_asset_certification::Asset;

let name = "World";
let asset = Asset::new(
    "index.html",
    format!("<html><body><h1>Hello {name}!</h1></body></html>").into_bytes(),
);
```

## Configuring asset certification

`AssetConfig` defines the configuration for any files that will be certified.
The configuration can either be matched to an individual file by path, or to
many files by a glob.

In both cases, the following options can be configured for each asset:

- `content_type`
  - Providing this option will certify and serve a `Content-Type` header with
    the provided value.
  - If this value is not provided, the `Content-Type` header will not be
    inserted.
  - If the `Content-Type` header is not sent to the browser, the browser will
    try to guess the content type based on the file extension, unless an
    `X-Content-Type-Options: nosniff` header is sent.
  - Not certifying the `Content-Type` header will also allow a malicious replica
    to insert its own `Content-Type` header, which could lead to a security
    vulnerability.
- `headers`
  - Any additional headers provided will be certified and served with the
    asset.
  - It's important to include any headers that can affect browser behavior,
    particularly [security headers](https://owasp.org/www-project-secure-headers/index.html).

### Configuring individual files

When configuring an individual file, the `path` property is provided and must
match the path passed into the `Asset` constructor in the previous step.

In addition to the common configuration options, individual assets also have
the option of registering the asset as a fallback response for a particular
scope. This can be used to configure 404 pages or single-page application
entry points, for example.

When serving assets, if a requested path does not exactly match any assets then
a search is conducted for an asset configured with the fallback scope that most
closely matches the requested asset's path.

For example, if a request is made for `/app.js` and no asset with that exact
path is found, an attempt will be made to serve an asset configured with a
fallback scope of `/`.

This will be done recursively until it's no longer
possible to find a valid fallback. For example, if a request is made for
`/assets/js/app/core/index.js` and no asset with that exact path is found, then
the search will check for assets configured with the following fallback scopes,
in order:

- `/assets/js/app/core`
- `/assets/js/app`
- `/assets/js`
- `/assets`
- `/`

If multiple fallback assets are configured, the first one found will be used,
since that will be the most specific one available for that path. If no asset is
found with any of these fallback scopes, no response will be returned.

It's also possible to register aliases for an asset. This can be useful for
configuring multiple paths that should serve the same asset. For example, if an
asset is configured with the path `index.html`, it can be aliased by the path
`/`.

The following example configures an individual HTML file to be served by the
on the `/index.html` path, in addition to serving as the fallback for the `/`
scope and setting `/` as an alias for this asset.

```rust
use ic_asset_certification::{AssetConfig, AssetFallbackConfig};

let config = AssetConfig::File {
    path: "index.html".to_string(),
    content_type: Some("text/html".to_string()),
    headers: vec![
        ("Cache-Control".to_string(), "public, no-cache, no-store".to_string()),
    ],
    fallback_for: vec![AssetFallbackConfig {
        scope: "/".to_string(),
    }],
    aliased_by: vec!["/".to_string()],
};
```

It's also possible to configure multiple fallbacks for a single asset. The
following example configures an individual HTML file to be served by the on the
`/404.html` path, in addition to serving as the fallback for the `/js` and `/css`
scopes.

Any request to paths starting in `/js` and `/css` directories that don't exactly
match an asset will be routed to the `/404.html` asset.

Multiple aliases are also configured for this asset, namely:

- `/404`,
- `/404/`,
- `/404.html`
- `/not-found`
- `/not-found/`
- `/not-found/index.html`

Requests to any of those aliases will serve the `/404.html` asset.

```rust
use ic_asset_certification::{AssetConfig, AssetFallbackConfig};

let config = AssetConfig::File {
    path: "404.html".to_string(),
    content_type: Some("text/html".to_string()),
    headers: vec![
        ("Cache-Control".to_string(), "public, no-cache, no-store".to_string()),
    ],
    fallback_for: vec![
        AssetFallbackConfig {
            scope: "/css".to_string(),
        },
        AssetFallbackConfig {
            scope: "/js".to_string(),
        },
    ],
    aliased_by: vec![
        "/404".to_string(),
        "/404/".to_string(),
        "/404.html".to_string(),
        "/not-found".to_string(),
        "/not-found/".to_string(),
        "/not-found/index.html".to_string(),
    ],
};
```

### Configuring file patterns

When configuring file patterns, the `pattern` property is provided. This
property is a glob pattern that will be used to match multiple files.

Standard Unix-style glob syntax is supported:

- `?` matches any single character.
- `*` matches zero or more characters.
- `**` recursively matches directories but is only legal in three
  situations.
  - If the glob starts with `**/`, then it matches all directories.
    For example, `**/foo` matches `foo` and `bar/foo` but not
    `foo/bar`.
  - If the glob ends with `/**`, then it matches all sub-entries.
    For example, `foo/**` matches `foo/a` and `foo/a/b`, but not
    `foo`.
  - If the glob contains `/**/` anywhere within the pattern, then it
    matches zero or more directories.
  - Using `**` anywhere else is illegal.
  - The glob `**` is allowed and means "match everything".
- `{a,b}` matches `a` or `b` where `a` and `b` are arbitrary glob
  patterns. (N.B. Nesting {...} is not currently allowed.)
- `[ab]` matches `a` or `b` where `a` and `b` are characters.
- `[!ab]` to match any character except for `a` and `b`.
- Metacharacters such as `*` and `?` can be escaped with character
  class notation. e.g., `[*]` matches `*`.

For example, the following pattern will match all `.js` files in the `js`
directory:

```rust
use ic_asset_certification::AssetConfig;

let config = AssetConfig::Pattern {
    pattern: "js/*.js".to_string(),
    content_type: Some("application/javascript".to_string()),
    headers: vec![
        ("Cache-Control".to_string(), "public, max-age=31536000, immutable".to_string()),
    ],
};
```

### Configuring redirects

Redirects can be configured using the `AssetConfig::Redirect` variant. This
variant takes a `from` and `to` paths, and a redirect `kind`.
When a request is made to the `from` path, the client will be redirected to the
`to` path. The `AssetConfig::Redirect` config is not matched against any `Asset`s.

Redirects can be configured as either permanent
or temporary.

The browser will cache permanent redirects and will not request the old
location again. This is useful when the resource has permanently moved to a new
location. The browser will update its bookmarks and search engine results.

See the
[MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/301)
for more information on permanent redirects.

The browser will not cache temporary redirects and will request
the old location again. This is useful when the resource has temporarily moved
to a new location. The browser will not update its bookmarks and search engine
results.

See the
[MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307)
for more information on temporary redirects.

The following example configures a permanent redirect from `/old` to `/new`:

```rust
use ic_asset_certification::{AssetConfig, AssetRedirectKind};

let config = AssetConfig::Redirect {
  from: "/old".to_string(),
  to: "/new".to_string(),
  kind: AssetRedirectKind::Permanent,
};
```

## Inserting assets into the asset router

The `AssetRouter` is responsible for certifying responses and routing requests to
the appropriate response.

Assets can be inserted one by one using the `certify_asset` method:

```rust
use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter};

let mut asset_router = AssetRouter::default();

let asset = Asset::new(
    "index.html",
    b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
);

let asset_config = AssetConfig::File {
    path: "index.html".to_string(),
    content_type: Some("text/html".to_string()),
    headers: vec![
        ("Cache-Control".to_string(), "public, no-cache, no-store".to_string()),
    ],
    fallback_for: vec![AssetFallbackConfig {
        scope: "/".to_string(),
    }],
  aliased_by: vec!["/".to_string()],
};

asset_router.certify_asset(asset, Some(asset_config)).unwrap();
```

Or in bulk using the `certify_assets` method:

```rust
use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind};

let mut asset_router = AssetRouter::default();

let assets = vec![
    Asset::new(
        "index.html",
        b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
    ),
    Asset::new(
        "app.js",
        b"console.log('Hello World!');".as_slice(),
    ),
    Asset::new(
      "css/app-ba74b708.css",
      b"html,body{min-height:100vh;}".as_slice(),
    ),
];

let asset_configs = vec![
    AssetConfig::File {
        path: "index.html".to_string(),
        content_type: Some("text/html".to_string()),
        headers: vec![(
            "cache-control".to_string(),
            "public, no-cache, no-store".to_string(),
        )],
        fallback_for: vec![AssetFallbackConfig {
            scope: "/".to_string(),
        }],
        aliased_by: vec!["/".to_string()],
    },
    AssetConfig::Pattern {
        pattern: "**/*.js".to_string(),
        content_type: Some("text/javascript".to_string()),
        headers: vec![(
            "cache-control".to_string(),
            "public, max-age=31536000, immutable".to_string(),
        )],
    },
    AssetConfig::Pattern {
        pattern: "**/*.css".to_string(),
        content_type: Some("text/css".to_string()),
        headers: vec![(
            "cache-control".to_string(),
            "public, max-age=31536000, immutable".to_string(),
        )],
    },
    AssetConfig::Redirect {
        from: "/old".to_string(),
        to: "/new".to_string(),
        kind: AssetRedirectKind::Permanent,
    },
];

asset_router.certify_assets(assets, asset_configs).unwrap();
```

After certifying assets, make sure to set the canister's
certified data:

```rust
use ic_cdk::api::set_certified_data;

set_certified_data(&asset_router.root_hash());
```

After creating the `AssetRouter`, it's also possible to initialize the router
with an `HttpCertificationTree`. This is useful when direct access to the
`HttpCertificationTree` is required for certifying `HttpRequest`s and
`HttpResponse`s outside of the `AssetRouter`.

The initialization of the `AssetRouter` must be done before certifying any assets
as the initialization function will reset the internal state of the `AssetRouter`.

```rust
use std::{cell::RefCell, rc::Rc};
use ic_http_certification::HttpCertificationTree;
use ic_asset_certification::AssetRouter;

let mut http_certification_tree: Rc<RefCell<HttpCertificationTree>> = Default::default();
let mut asset_router = AssetRouter::default();

asset_router.init_with_tree(http_certification_tree.clone());
```

## Serving assets

Assets can be served by calling the `serve_asset` method on the `AssetRouter`:

```rust
use ic_http_certification::HttpRequest;
use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter};

let mut asset_router = AssetRouter::default();

let asset = Asset::new(
    "index.html",
    b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
);

let asset_config = AssetConfig::File {
    path: "index.html".to_string(),
    content_type: Some("text/html".to_string()),
    headers: vec![
        ("Cache-Control".to_string(), "public, no-cache, no-store".to_string()),
    ],
    fallback_for: vec![AssetFallbackConfig {
        scope: "/".to_string(),
    }],
    aliased_by: vec!["/".to_string()],
};

let http_request = HttpRequest {
    method: "GET".to_string(),
    url: "/".to_string(),
    headers: vec![],
    body: vec![],
};

asset_router.certify_asset(asset, Some(asset_config)).unwrap();

let (response, witness, expr_path) = asset_router.serve_asset(&http_request).unwrap();
```

Some additional steps are then required to prepare the response for sending:

- get the canister's certificate data
- CBOR-encode the witness
- CBOR-encode the expression path
- Add the certificate header to the response

```rust
const IC_CERTIFICATE_HEADER: &str = "IC-Certificate";
fn add_certificate_header(response: &mut HttpResponse, witness: &HashTree, expr_path: &[String]) {
    let certified_data = data_certificate().expect("No data certificate available");
    let witness = cbor_encode(witness);
    let expr_path = cbor_encode(&expr_path);

    response.headers.push((
        IC_CERTIFICATE_HEADER.to_string(),
        format!(
            "certificate=:{}:, tree=:{}:, expr_path=:{}:, version=2",
            BASE64.encode(certified_data),
            BASE64.encode(witness),
            BASE64.encode(expr_path)
        ),
    ));
}

// Encoding
fn cbor_encode(value: &impl Serialize) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer
        .self_describe()
        .expect("Failed to self describe CBOR");
    value
        .serialize(&mut serializer)
        .expect("Failed to serialize value");
    serializer.into_inner()
}

add_certificate_header(&mut response, &witness, &expr_path);
```
