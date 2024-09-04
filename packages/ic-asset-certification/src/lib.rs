//!
//! # Asset Certification
//!
//! ## Overview
//!
//! Asset certification is a specialized form of
//! [HTTP Certification](https://internetcomputer.org/docs/current/developer-docs/http-compatible-canisters/custom-http-canisters)
//! purpose-built for certifying static assets in ICP canisters.
//!
//! The `ic-asset-certification` crate provides the necessary functionality to
//! certify and serve static assets from Rust canisters.
//!
//! This is implemented in the following steps:
//!
//! 1. [Preparing assets](#preparing-assets)
//! 2. [Configuring asset certification](#configuring-asset-certification)
//! 3. [Inserting assets into the asset router](#inserting-assets-into-the-asset-router)
//! 4. [Serving assets](#serving-assets)
//!
//! For canisters that need it, it's also possible to [delete assets](#deleting-assets).
//!
//! ## Preparing assets
//!
//! This library is unopinionated about where assets come from, so that is not
//! covered in detail here, but there are three main options:
//!
//! - Embedding assets in the canister at compile time:
//!   - [include_bytes!](https://doc.rust-lang.org/std/macro.include_bytes.html)
//!   - [include_dir!](https://docs.rs/include_dir/latest/include_dir/index.html)
//! - Uploading assets via canister endpoints at runtime.
//!   - The [DFX asset canister](https://github.com/dfinity/sdk/blob/master/docs/design/asset-canister-interface.md) is a good example of this approach.
//! - Generating assets dynamically in code, at runtime.
//!
//! With the assets in memory, they can be converted into the [Asset] type:
//!
//! ```rust
//! use ic_asset_certification::Asset;
//!
//! let asset = Asset::new(
//!     "index.html",
//!     b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
//! );
//! ```
//!
//! It is recommended to use references when including assets directly into the
//! canister, to avoid duplicating the content. This is particularly important for
//! larger assets.
//!
//! ```rust
//! use ic_asset_certification::Asset;
//!
//! let pretty_big_asset = include_bytes!("lib.rs");
//! let asset = Asset::new(
//!     "assets/pretty-big-asset.gz",
//!     pretty_big_asset.as_slice(),
//! );
//! ```
//!
//! In some cases, it may be necessary to use owned values, such as when assets are
//! dynamically generated or modified at runtime.
//!
//! ```rust
//! use ic_asset_certification::Asset;
//!
//! let name = "World";
//! let asset = Asset::new(
//!     "index.html",
//!     format!("<html><body><h1>Hello {name}!</h1></body></html>").into_bytes(),
//! );
//! ```
//!
//! ## Configuring asset certification
//!
//! [AssetConfig] defines the configuration for any files that will be certified.
//! The configuration can either be matched to an individual file by [path](AssetConfig::File), or to
//! many files by a [glob](AssetConfig::Pattern).
//!
//! In both cases, the following options can be configured for each asset:
//!
//! - `content_type`
//!   - Providing this option will certify and serve a `Content-Type` header with
//!     the provided value.
//!   - If this value is not provided, the `Content-Type` header will not be
//!     inserted.
//!   - If the `Content-Type` header is not sent to the browser, the browser will
//!     try to guess the content type based on the file extension, unless an
//!     `X-Content-Type-Options: nosniff` header is sent.
//!   - Not certifying the `Content-Type` header will also allow a malicious replica
//!     to insert its own `Content-Type` header, which could lead to a security
//!     vulnerability.
//! - `headers`
//!   - Any additional headers provided will be certified and served with the
//!     asset.
//!   - It's important to include any headers that can affect browser behavior,
//!     particularly [security headers](https://owasp.org/www-project-secure-headers/index.html).
//! - `encodings`
//!     - A list of alternative encodings that can be used to serve the asset.
//!     - Each entry is a tuple of the [encoding name](AssetEncoding) and the file
//!       extension used in the file path, that can be conveniently created with
//!       the `default_config` factory method. For example, to include Brotli and Gzip encodings:
//!       `vec![AssetEncoding::Brotli.default_config(), AssetEncoding::Gzip.default_config()]`.
//!     - The default file extensions for each encoding are:
//!         - Brotli: `br`
//!         - Gzip: `gz`
//!         - Deflate: `zz`
//!         - Zstd: `zst`
//!     - Alternatively, a custom file extension can be provided for each encoding
//!       by using the `custom_config` factory method. For example, to include a custom
//!       file extension for Brotli and Gzip encodings:
//!       `vec![AssetEncoding::Brotli.custom_config("brotli"), AssetEncoding::Gzip.custom_config("gzip")]`.
//!     - Each encoding referenced must be provided to the asset router as a
//!       separate file with the same filename as the original file, but with an
//!       additional file extension matching the configuration. For example, if the
//!       current matched file is named `file.html`, then the asset router will
//!       look for `file.html.br` and `file.html.gz`.
//!     - If the file is found, the asset will be certified and served with the
//!       provided encoding according to the `Accept-Encoding`.
//!     - Encodings are prioritized in the following order:
//!         - Brotli
//!         - Zstd
//!         - Gzip
//!         - Deflate
//!         - Identity
//!     - The asset router will return the highest priority encoding that has been
//!       certified and is supported by the client.
//!
//! ### Configuring individual files
//!
//! When configuring an individual file, the [path](AssetConfig::File::path) property is provided and must
//! match the path passed into the [Asset] constructor in the previous step.
//!
//! In addition to the common configuration options, individual assets also have
//! the option of registering the asset as a [fallback response](AssetConfig::File::fallback_for) for a particular
//! scope. This can be used to configure 404 pages or single-page application
//! entry points, for example.
//!
//! When serving assets, if a requested path does not exactly match any assets then
//! a search is conducted for an asset configured with the fallback scope that most
//! closely matches the requested asset's path.
//!
//! For example, if a request is made for `/app.js` and no asset with that exact
//! path is found, an attempt will be made to serve an asset configured with a
//! fallback scope of `/`.
//!
//! This will be done recursively until it's no longer
//! possible to find a valid fallback. For example, if a request is made for
//! `/assets/js/app/core/index.js` and no asset with that exact path is found, then
//! the search will check for assets configured with the following fallback scopes,
//! in order:
//!
//! - `/assets/js/app/core`
//! - `/assets/js/app`
//! - `/assets/js`
//! - `/assets`
//! - `/`
//!
//! If multiple fallback assets are configured, the first one found will be used,
//! since that will be the most specific one available for that path. If no asset is
//! found with any of these fallback scopes, no response will be returned.
//!
//! It's also possible to register aliases for an asset. This can be useful for
//! configuring multiple paths that should serve the same asset. For example, if an
//! asset is configured with the path `index.html`, it can be aliased by the path
//! `/`.
//!
//! The following example configures an individual HTML file to be served by the
//! on the `/index.html` path, in addition to serving as the fallback for the `/`
//! scope and setting `/` as an alias for this asset.
//!
//! ```rust
//! use ic_asset_certification::{AssetConfig, AssetFallbackConfig, AssetEncoding};
//!
//! let config = AssetConfig::File {
//!     path: "index.html".to_string(),
//!     content_type: Some("text/html".to_string()),
//!     headers: vec![
//!         ("Cache-Control".to_string(), "public, no-cache, no-store".to_string()),
//!     ],
//!     fallback_for: vec![AssetFallbackConfig {
//!         scope: "/".to_string(),
//!     }],
//!     aliased_by: vec!["/".to_string()],
//!     encodings: vec![
//!         AssetEncoding::Brotli.default_config(),
//!         AssetEncoding::Gzip.default_config(),
//!     ],
//! };
//! ```
//!
//! It's also possible to configure multiple fallbacks for a single asset. The
//! following example configures an individual HTML file to be served by the on the
//! `/404.html` path, in addition to serving as the fallback for the `/js` and `/css`
//! scopes.
//!
//! Any request to paths starting in `/js` and `/css` directories that don't exactly
//! match an asset will be routed to the `/404.html` asset.
//!
//! Multiple aliases are also configured for this asset, namely:
//! - `/404`,
//! - `/404/`,
//! - `/404.html`
//! - `/not-found`
//! - `/not-found/`
//! - `/not-found/index.html`
//!
//! Requests to any of those aliases will serve the `/404.html` asset.
//!
//! ```rust
//! use ic_asset_certification::{AssetConfig, AssetFallbackConfig, AssetEncoding};
//!
//! let config = AssetConfig::File {
//!     path: "404.html".to_string(),
//!     content_type: Some("text/html".to_string()),
//!     headers: vec![
//!         ("Cache-Control".to_string(), "public, no-cache, no-store".to_string()),
//!     ],
//!     fallback_for: vec![
//!         AssetFallbackConfig {
//!             scope: "/css".to_string(),
//!         },
//!         AssetFallbackConfig {
//!             scope: "/js".to_string(),
//!         },
//!     ],
//!     aliased_by: vec![
//!         "/404".to_string(),
//!         "/404/".to_string(),
//!         "/404.html".to_string(),
//!         "/not-found".to_string(),
//!         "/not-found/".to_string(),
//!         "/not-found/index.html".to_string(),
//!     ],
//!     encodings: vec![
//!         AssetEncoding::Brotli.default_config(),
//!         AssetEncoding::Gzip.default_config(),
//!     ],
//! };
//! ```
//!
//! ### Configuring file patterns
//!
//! When configuring file patterns, the `pattern` property is provided. This
//! property is a glob pattern that will be used to match multiple files.
//!
//! Standard Unix-style glob syntax is supported:
//!
//! - `?` matches any single character.
//! - `*` matches zero or more characters.
//! - `**` recursively matches directories but is only legal in three
//!   situations.
//!   - If the glob starts with '**\/`, then it matches all directories.
//!   For example, `**\/foo` matches `foo` and `bar\/foo` but not
//!   `foo\/bar\`.
//! - If the glob ends with `\/**`, then it matches all sub-entries.
//!   For example, `foo\/\**` matches `foo\/a` and `foo\/a\/b`, but not
//!   `foo`.
//! - If the glob contains `\/\**\/` anywhere within the pattern, then it
//!   matches zero or more directories.
//! - Using `**` anywhere else is illegal.
//! - The glob `**` is allowed and means "match everything".
//! - `{a,b}` matches `a` or `b` where `a` and `b` are arbitrary glob
//! patterns. (N.B. Nesting {...} is not currently allowed.)
//! - `[ab]` matches `a` or `b` where `a` and `b` are characters.
//! - `[!ab]` to match any character except for `a` and `b`.
//! - Metacharacters such as `*` and `?` can be escaped with character
//! class notation. e.g., `[*]` matches `*`.
//!
//! For example, the following pattern will match all `.js` files in the `js`
//! directory:
//!
//! ```rust
//! use ic_asset_certification::{AssetConfig, AssetEncoding};
//!
//! let config = AssetConfig::Pattern {
//!     pattern: "js/*.js".to_string(),
//!     content_type: Some("application/javascript".to_string()),
//!     headers: vec![
//!         ("Cache-Control".to_string(), "public, max-age=31536000, immutable".to_string()),
//!     ],
//!     encodings: vec![
//!         AssetEncoding::Brotli.default_config(),
//!         AssetEncoding::Gzip.default_config(),
//!     ],
//! };
//! ```
//!
//! ### Configuring redirects
//!
//! Redirects can be configured using the [AssetConfig::Redirect] variant. This
//! variant takes a `from` and `to` paths, and a redirect [kind](AssetRedirectKind).
//! When a request is made to the `from` path, the client will be redirected to the
//! `to` path. The [AssetConfig::Redirect] config is not matched against any [Asset]s.
//!
//! Redirects can be configured as either [permanent](AssetRedirectKind::Permanent)
//! or [temporary](AssetRedirectKind::Temporary).
//!
//! The browser will cache permanent redirects and will not request the old
//! location again. This is useful when the resource has permanently moved to a new
//! location. The browser will update its bookmarks and search engine results.
//!
//! See the
//! [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/301)
//! for more information on permanent redirects.
//!
//! The browser will not cache temporary redirects and will request
//! the old location again. This is useful when the resource has temporarily moved
//! to a new location. The browser will not update its bookmarks and search engine
//! results.
//!
//! See the
//! [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307)
//! for more information on temporary redirects.
//!
//! The following example configures a permanent redirect from `/old` to `/new`:
//!
//! ```rust
//! use ic_asset_certification::{AssetConfig, AssetRedirectKind};
//!
//! let config = AssetConfig::Redirect {
//!     from: "/old".to_string(),
//!     to: "/new".to_string(),
//!     kind: AssetRedirectKind::Permanent,
//! };
//! ```
//!
//! ## Inserting assets into the asset router
//!
//! The [AssetRouter] is responsible for certifying responses and routing requests to
//! the appropriate response.
//!
//! Assets can be inserted using the
//! [certify_assets](AssetRouter::certify_assets) method:
//!
//! ```rust
//! use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind, AssetEncoding};
//!
//! let mut asset_router = AssetRouter::default();
//!
//! let assets = vec![
//!     Asset::new(
//!         "index.html",
//!         b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
//!     ),
//!     Asset::new(
//!         "index.html.gz",
//!         &[0, 1, 2, 3, 4, 5]
//!     ),
//!     Asset::new(
//!         "index.html.br",
//!         &[6, 7, 8, 9, 10, 11]
//!     ),
//!     Asset::new(
//!         "app.js",
//!         b"console.log('Hello World!');".as_slice(),
//!     ),
//!     Asset::new(
//!         "app.js.gz",
//!         &[12, 13, 14, 15, 16, 17],
//!     ),
//!     Asset::new(
//!         "app.js.br",
//!         &[18, 19, 20, 21, 22, 23],
//!     ),
//!     Asset::new(
//!         "css/app-ba74b708.css",
//!         b"html,body{min-height:100vh;}".as_slice(),
//!     ),
//!     Asset::new(
//!         "css/app-ba74b708.css.gz",
//!         &[24, 25, 26, 27, 28, 29],
//!     ),
//!     Asset::new(
//!         "css/app-ba74b708.css.br",
//!         &[30, 31, 32, 33, 34, 35],
//!     ),
//! ];
//!
//! let asset_configs = vec![
//!     AssetConfig::File {
//!         path: "index.html".to_string(),
//!         content_type: Some("text/html".to_string()),
//!         headers: vec![(
//!             "cache-control".to_string(),
//!             "public, no-cache, no-store".to_string(),
//!         )],
//!         fallback_for: vec![AssetFallbackConfig {
//!             scope: "/".to_string(),
//!         }],
//!         aliased_by: vec!["/".to_string()],
//!         encodings: vec![
//!             AssetEncoding::Brotli.default_config(),
//!             AssetEncoding::Gzip.default_config(),
//!         ],
//!     },
//!     AssetConfig::Pattern {
//!         pattern: "**/*.js".to_string(),
//!         content_type: Some("text/javascript".to_string()),
//!         headers: vec![(
//!             "cache-control".to_string(),
//!             "public, max-age=31536000, immutable".to_string(),
//!         )],
//!         encodings: vec![
//!             AssetEncoding::Brotli.default_config(),
//!             AssetEncoding::Gzip.default_config(),
//!         ],
//!     },
//!     AssetConfig::Pattern {
//!         pattern: "**/*.css".to_string(),
//!         content_type: Some("text/css".to_string()),
//!         headers: vec![(
//!             "cache-control".to_string(),
//!             "public, max-age=31536000, immutable".to_string(),
//!         )],
//!         encodings: vec![
//!             AssetEncoding::Brotli.default_config(),
//!             AssetEncoding::Gzip.default_config(),
//!         ],
//!     },
//!     AssetConfig::Redirect {
//!         from: "/old".to_string(),
//!         to: "/new".to_string(),
//!         kind: AssetRedirectKind::Permanent,
//!     },
//! ];
//!
//! asset_router.certify_assets(assets, asset_configs).unwrap();
//! ```
//!
//! After certifying assets, make sure to set the canister's
//! certified data:
//!
//! ```ignore
//! use ic_cdk::api::set_certified_data;
//!
//! set_certified_data(&asset_router.root_hash());
//! ```
//!
//! It's also possible to initialize the router with an
//! [HttpCertificationTree](ic_http_certification::HttpCertificationTree). This is
//! useful when direct access to the
//! [HttpCertificationTree](ic_http_certification::HttpCertificationTree) is required
//! for certifying [HttpRequest](ic_http_certification::HttpRequest)s and
//! [HttpResponse](ic_http_certification::HttpResponse)s outside of the [AssetRouter].
//!
//! ```rust
//! use std::{cell::RefCell, rc::Rc};
//! use ic_http_certification::HttpCertificationTree;
//! use ic_asset_certification::AssetRouter;
//!
//! let mut http_certification_tree: Rc<RefCell<HttpCertificationTree>> = Default::default();
//! let mut asset_router = AssetRouter::with_tree(http_certification_tree.clone());
//! ```
//!
//! ## Serving assets
//!
//! Assets can be served by calling the `serve_asset` method on the `AssetRouter`.
//! This method will return a response, a witness and an expression path, which can be used
//! alongside the canister's data certificate to add the required certificate header to the response.
//!
//! ```rust
//! use ic_http_certification::{HttpRequest, utils::add_certificate_header};
//! use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter};
//!
//! let mut asset_router = AssetRouter::default();
//!
//! let asset = Asset::new(
//!     "index.html",
//!     b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
//! );
//!
//! let asset_config = AssetConfig::File {
//!     path: "index.html".to_string(),
//!     content_type: Some("text/html".to_string()),
//!     headers: vec![
//!         ("Cache-Control".to_string(), "public, no-cache, no-store".to_string()),
//!     ],
//!     fallback_for: vec![AssetFallbackConfig {
//!         scope: "/".to_string(),
//!     }],
//!     aliased_by: vec!["/".to_string()],
//!     encodings: vec![],
//! };
//!
//! let http_request = HttpRequest::get("/").build();
//!
//! asset_router.certify_assets(vec![asset], vec![asset_config]).unwrap();
//!
//! let (mut response, witness, expr_path) = asset_router.serve_asset(&http_request).unwrap();
//!
//! // this should normally be retrieved using `ic_cdk::api::data_certificate()`.
//! let data_certificate = vec![1, 2, 3];
//! add_certificate_header(
//!     data_certificate,
//!     &mut response,
//!     &witness,
//!     &expr_path,
//! );
//!```
//!
//! ## Deleting assets
//!
//! Deleting assets is similar to (certifying them)[#inserting-assets-into-the-asset-router].
//!
//! Depending on the configuration provided to the [certify_assets](AssetRouter::certify_assets) function,
//! multiple responses may be generated for the same asset. To ensure that all generated responses are deleted,
//! the [delete_assets](AssetRouter::delete_assets) function accepts the same configuration.
//!
//! If a configuration different to the one used to certify assets in the first place is provided,
//! one of two things can happen.
//!
//! If the configuration inclues a file that was not certified in the first place, it will be silently ignored.
//! For example, if the configuration provided to `certify_assets` includes the Brotli and Gzip encodings, but the
//! configuration provided to `delete_assets` includes Brotli, Gzip and Deflate, the Brotli and Gzip encoded files will be deleted, while the Deflate file is ignored, since it doesn't exist.
//!
//! If the configuration excludes a file that was certified, it will not be deleted. For example, if the configuration,
//! provided to `certify_assets` includes the Brotli and Gzip encodings, but the configuration provided to `delete_assets`
//! only includes Brotli, then the Gzip file will not be deleted.
//!
//! Using the same base example used to demonstrate certifying assets:
//!
//! ```rust
//! use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind, AssetEncoding};
//!
//! let mut asset_router = AssetRouter::default();
//!
//! let assets = vec![
//!     Asset::new(
//!         "index.html",
//!         b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
//!     ),
//!     Asset::new(
//!         "index.html.gz",
//!         &[0, 1, 2, 3, 4, 5]
//!     ),
//!     Asset::new(
//!         "index.html.br",
//!         &[6, 7, 8, 9, 10, 11]
//!     ),
//!     Asset::new(
//!         "app.js",
//!         b"console.log('Hello World!');".as_slice(),
//!     ),
//!     Asset::new(
//!         "app.js.gz",
//!         &[12, 13, 14, 15, 16, 17],
//!     ),
//!     Asset::new(
//!         "app.js.br",
//!         &[18, 19, 20, 21, 22, 23],
//!     ),
//!     Asset::new(
//!         "css/app-ba74b708.css",
//!         b"html,body{min-height:100vh;}".as_slice(),
//!     ),
//!     Asset::new(
//!         "css/app-ba74b708.css.gz",
//!         &[24, 25, 26, 27, 28, 29],
//!     ),
//!     Asset::new(
//!         "css/app-ba74b708.css.br",
//!         &[30, 31, 32, 33, 34, 35],
//!     ),
//! ];
//!
//! let asset_configs = vec![
//!     AssetConfig::File {
//!         path: "index.html".to_string(),
//!         content_type: Some("text/html".to_string()),
//!         headers: vec![(
//!             "cache-control".to_string(),
//!             "public, no-cache, no-store".to_string(),
//!         )],
//!         fallback_for: vec![AssetFallbackConfig {
//!             scope: "/".to_string(),
//!         }],
//!         aliased_by: vec!["/".to_string()],
//!         encodings: vec![
//!             AssetEncoding::Brotli.default_config(),
//!             AssetEncoding::Gzip.default_config(),
//!         ],
//!     },
//!     AssetConfig::Pattern {
//!         pattern: "**/*.js".to_string(),
//!         content_type: Some("text/javascript".to_string()),
//!         headers: vec![(
//!             "cache-control".to_string(),
//!             "public, max-age=31536000, immutable".to_string(),
//!         )],
//!         encodings: vec![
//!             AssetEncoding::Brotli.default_config(),
//!             AssetEncoding::Gzip.default_config(),
//!         ],
//!     },
//!     AssetConfig::Pattern {
//!         pattern: "**/*.css".to_string(),
//!         content_type: Some("text/css".to_string()),
//!         headers: vec![(
//!             "cache-control".to_string(),
//!             "public, max-age=31536000, immutable".to_string(),
//!         )],
//!         encodings: vec![
//!             AssetEncoding::Brotli.default_config(),
//!             AssetEncoding::Gzip.default_config(),
//!         ],
//!     },
//!     AssetConfig::Redirect {
//!         from: "/old".to_string(),
//!         to: "/new".to_string(),
//!         kind: AssetRedirectKind::Permanent,
//!     },
//! ];
//!
//! asset_router.certify_assets(assets, asset_configs).unwrap();
//! ```
//!
//! To delete the `index.html` asset, along with the fallback configuration for the `/` scope, the alias `/` and the alternative encodings:
//!
//! ```rust
//! # use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind, AssetEncoding};
//!
//! # let mut asset_router = AssetRouter::default();
//!
//! asset_router
//!     .delete_assets(
//!         vec![
//!             Asset::new(
//!                 "index.html",
//!                 b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
//!             ),
//!             Asset::new("index.html.gz", &[0, 1, 2, 3, 4, 5]),
//!             Asset::new("index.html.br", &[6, 7, 8, 9, 10, 11]),
//!         ],
//!         vec![AssetConfig::File {
//!             path: "index.html".to_string(),
//!             content_type: Some("text/html".to_string()),
//!             headers: vec![(
//!                 "cache-control".to_string(),
//!                 "public, no-cache, no-store".to_string(),
//!             )],
//!             fallback_for: vec![AssetFallbackConfig {
//!                 scope: "/".to_string(),
//!             }],
//!             aliased_by: vec!["/".to_string()],
//!             encodings: vec![
//!                 AssetEncoding::Brotli.default_config(),
//!                 AssetEncoding::Gzip.default_config(),
//!             ],
//!         }],
//!     )
//!     .unwrap();
//! ```
//!
//! To delete the `app.js`asset, along with the alternative encodings:
//!
//! ```rust
//! # use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind, AssetEncoding};
//!
//! # let mut asset_router = AssetRouter::default();
//!
//! asset_router
//!     .delete_assets(
//!         vec![
//!             Asset::new("app.js", b"console.log('Hello World!');".as_slice()),
//!             Asset::new("app.js.gz", &[12, 13, 14, 15, 16, 17]),
//!             Asset::new("app.js.br", &[18, 19, 20, 21, 22, 23]),
//!         ],
//!         vec![AssetConfig::Pattern {
//!             pattern: "**/*.js".to_string(),
//!             content_type: Some("text/javascript".to_string()),
//!             headers: vec![(
//!                 "cache-control".to_string(),
//!                 "public, max-age=31536000, immutable".to_string(),
//!             )],
//!             encodings: vec![
//!                 AssetEncoding::Brotli.default_config(),
//!                 AssetEncoding::Gzip.default_config(),
//!             ],
//!         }],
//!     )
//!     .unwrap();
//! ```
//!
//! To delete the `css/app-ba74b708.css` asset, along with the alternative encodings:
//!
//! ```rust
//! # use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind, AssetEncoding};
//!
//! # let mut asset_router = AssetRouter::default();
//!
//! asset_router.delete_assets(
//!     vec![
//!         Asset::new(
//!             "css/app-ba74b708.css",
//!             b"html,body{min-height:100vh;}".as_slice(),
//!         ),
//!         Asset::new(
//!             "css/app-ba74b708.css.gz",
//!             &[24, 25, 26, 27, 28, 29],
//!         ),
//!         Asset::new(
//!             "css/app-ba74b708.css.br",
//!             &[30, 31, 32, 33, 34, 35],
//!         ),
//!     ],
//!     vec![
//!         AssetConfig::Pattern {
//!             pattern: "**/*.css".to_string(),
//!             content_type: Some("text/css".to_string()),
//!             headers: vec![(
//!                 "cache-control".to_string(),
//!                 "public, max-age=31536000, immutable".to_string(),
//!             )],
//!             encodings: vec![
//!                 AssetEncoding::Brotli.default_config(),
//!                 AssetEncoding::Gzip.default_config(),
//!             ],
//!         },
//!     ]
//! ).unwrap();
//! ```
//!
//! And finally, to delete the `/old` redirect:
//!
//! ```rust
//! # use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind, AssetEncoding};
//!
//! # let mut asset_router = AssetRouter::default();
//!
//! asset_router
//!     .delete_assets(
//!         vec![],
//!         vec![AssetConfig::Redirect {
//!             from: "/old".to_string(),
//!             to: "/new".to_string(),
//!             kind: AssetRedirectKind::Permanent,
//!         }],
//!     )
//!     .unwrap();
//! ```
//!
//! After deleting any assets, make sure to set the canister's
//! certified data again:
//!
//! ```ignore
//! use ic_cdk::api::set_certified_data;
//!
//! set_certified_data(&asset_router.root_hash());
//! ```

#![deny(missing_docs, missing_debug_implementations, rustdoc::all, clippy::all)]

mod asset;
mod asset_config;
mod asset_router;
mod error;

pub use asset::*;
pub use asset_config::*;
pub use asset_router::*;
pub use error::*;
