# Serving static assets over HTTP

## Overview

This guide walks through an example project that demonstrates how to create a canister that can serve certified static assets (HTML, CSS, JS) over HTTP. The example project presents a very simple single-page JavaScript application. Assets are embedded into the canister when it is compiled.

This is not a beginner's canister development guide. Many foundational concepts that a relatively experienced canister developer should already know will be omitted. Concepts specific to asset certification will be called out here and can help to understand the [full code example](https://github.com/dfinity/response-verification/tree/main/examples/http-certification/assets).

The certification and serving of assets is based on the high-level [`ic-asset-certification` crate](https://crates.io/crates/ic-asset-certification).

If more flexibility than what this crate provides is needed, the lower-level [`ic-http-certification` crate](https://crates.io/crates/ic-http-certification) can be used. Be sure to check out the ["Custom HTTP Canisters"](https://internetcomputer.org/docs/current/developer-docs/http-compatible-canisters/custom-http-canisters) and ["Custom asset canisters"](https://internetcomputer.org/docs/current/developer-docs/web-apps/http-compatible-canisters/serving-static-assets-over-http) guides to learn more about how to use that library for serving assets.

## The frontend assets

The frontend project used for this example is a simple starter project generated with `npx degit solidjs/templates/ts my-app`. The only changes that have been made are in the `vite.config.ts` file. The `vite-plugin-compression` plugin was added and configured to generate Gzip and Brotli encoded assets, alongside the original assets. The `ext` configuration affects the file extension and it's important to keep this consistent with the backend canister code that will be seen later in this guide.

```ts
import { defineConfig } from 'vite';
import solidPlugin from 'vite-plugin-solid';

// import the compression plugin
import viteCompressionPlugin from 'vite-plugin-compression';

export default defineConfig({
  plugins: [
    solidPlugin(),

    // setup Gzip compression
    viteCompressionPlugin({
      algorithm: 'gzip',
      // this extension will be referenced later in the canister code
      ext: '.gzip',
      // ensure to not delete the original files
      deleteOriginFile: false,
      threshold: 0,
    }),

    // setup Brotli compression
    viteCompressionPlugin({
      algorithm: 'brotliCompress',
      // this extension will be referenced later in the canister code
      ext: '.br',
      // ensure to not delete the original files
      deleteOriginFile: false,
      threshold: 0,
    }),
  ],
  server: {
    port: 3000,
  },
  build: {
    target: 'esnext',
  },
});
```

The rest of this guide will address the canister code.

## Lifecycle hooks

The first thing to do when the canister bootstraps for the first time is to certify all the assets. This is done in the `init` hook. The `certify_all_assets` function will be covered in a later section.

The asset certification is not stored in stable memory so it's necessary to re-certify the assets after a canister upgrade. This is done in the `post_upgrade` hook.

```rust
#[init]
fn init() {
    certify_all_assets();
}

#[post_upgrade]
fn post_upgrade() {
    init();
}
```

## Canister endpoints

There is only one canister endpoint in this example to serve assets, `http_request` query endpoint. The `serve_assets` function will be covered in a later section.

```rust
#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    serve_asset(&req)
}
```

## Loading assets

Assets are embedded into the canister's Wasm at build time. This is achieved using the [`include_dir`](https://michael-f-bryan.github.io/include_dir/include_dir/index.html) crate. Note that this works fine for a small number of assets, but a larger number of assets may cause longer compile times, as mentioned in the [crate's documentation](https://michael-f-bryan.github.io/include_dir/include_dir/index.html#compile-time-considerations).

The assets are imported from the frontend build directory:

```rust
static ASSETS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../frontend/dist");
```

With the assets loaded, they need to be converted into the `Asset` type that the `ic-asset-certification` crate uses.

```rust
/// Rescursively collect all assets from the provided directory
fn collect_assets<'content, 'path>(
    dir: &'content Dir<'path>,
    assets: &mut Vec<Asset<'content, 'path>>,
) {
    for file in dir.files() {
        assets.push(Asset::new(file.path().to_string_lossy(), file.contents()));
    }

    for dir in dir.dirs() {
        collect_assets(dir, assets);
    }
}
```

## Certifying assets

Asset certification is configured using the `AssetConfig` type. This type is used to specify the content type, headers, and any fallbacks for each asset.

To handle common headers, a helper function `get_asset_headers` is used. The security headers added to responses are based on the [OWASP Secure Headers project](https://owasp.org/www-project-secure-headers/index.html).

These security headers have been included as a reasonably secure default for most static asset APIs. However, it's vitally important for developers to educate themselves and make informed decisions in the context of their own project's needs.

```rust
fn get_asset_headers(additional_headers: Vec<HeaderField>) -> Vec<HeaderField> {
    // set up the default headers and include additional headers provided by the caller
    let mut headers = vec![
        ("strict-transport-security".to_string(), "max-age=31536000; includeSubDomains".to_string()),
        ("x-frame-options".to_string(), "DENY".to_string()),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
        ("content-security-policy".to_string(), "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content".to_string()),
        ("referrer-policy".to_string(), "no-referrer".to_string()),
        ("permissions-policy".to_string(), "accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),fullscreen=(),gamepad=(),geolocation=(),gyroscope=(),layout-animations=(self),legacy-image-formats=(self),magnetometer=(),microphone=(),midi=(),oversized-images=(self),payment=(),picture-in-picture=(),publickey-credentials-get=(),speaker-selection=(),sync-xhr=(self),unoptimized-images=(self),unsized-media=(self),usb=(),screen-wake-lock=(),web-share=(),xr-spatial-tracking=()".to_string()),
        ("cross-origin-embedder-policy".to_string(), "require-corp".to_string()),
        ("cross-origin-opener-policy".to_string(), "same-origin".to_string()),
    ];
    headers.extend(additional_headers);

    headers
}
```

For the `index.html` file, the `AssetConfig::File` variant is used to target the configuration to that file specifically. The `fallback_for` field of this variant is used to specify that this asset is the fallback for all paths that don't exactly match a file and the `aliased_by` field is used to specify alternative paths that will serve the asset.

For the remaining files, they can all be configured in bulk using the `AssetConfig::Pattern` variant. This variant uses a glob pattern to match multiple files.

The `certify_all_assets` function performs the following steps:

1. Define the asset certification configurations.
2. Collect all assets from the frontend build directory.
3. Certify the assets using the `certify_assets` function from the `ic-asset-certification` crate.
4. Set the canister's certified data.

```rust
thread_local! {
    static HTTP_TREE: Rc<RefCell<HttpCertificationTree>> = Default::default();

    // initializing the asset router with an HTTP certification tree is optional.
    // if direct access to the HTTP certification tree is not needed for certifying
    // requests and responses outside of the asset router, then this step can be skipped.
    static ASSET_ROUTER: RefCell<AssetRouter<'static>> = RefCell::new(AssetRouter::with_tree(HTTP_TREE.with(|tree| tree.clone())));
}

const IMMUTABLE_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

fn certify_all_assets() {
    // 1. Define the asset certification configurations.
    let asset_configs = vec![
        AssetConfig::File {
            path: "index.html".to_string(),
            content_type: Some("text/html".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )]),
            fallback_for: vec![AssetFallbackConfig {
                scope: "/".to_string(),
            }],
            aliased_by: vec!["/".to_string()],
        },
        AssetConfig::Pattern {
            pattern: "**/*.js".to_string(),
            content_type: Some("text/javascript".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )]),
        },
        AssetConfig::Pattern {
            pattern: "**/*.css".to_string(),
            content_type: Some("text/css".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )]),
        },
        AssetConfig::Pattern {
            pattern: "**/*.ico".to_string(),
            content_type: Some("image/x-icon".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )]),
        },
        AssetConfig::Pattern {
            pattern: "**/*.svg".to_string(),
            content_type: Some("image/svg+xml".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )]),
        },
    ];

    // 2. Collect all assets from the frontend build directory.
    let mut assets = Vec::new();
    collect_assets(&ASSETS_DIR, &mut assets);

    ASSET_ROUTER.with_borrow_mut(|asset_router| {
        // 3. Certify the assets using the `certify_assets` function from the `ic-asset-certification` crate.
        if let Err(err) = asset_router.certify_assets(assets, asset_configs) {
            ic_cdk::trap(&format!("Failed to certify assets: {}", err));
        }

        // 4. Set the canister's certified data.
        set_certified_data(&asset_router.root_hash());
    });
}
```

## Serving assets

The `serve_asset` function is responsible for serving assets. It uses the `serve_asset` function from the `AssetRouter` to serve the assets. This function returns the `HttpResponse`, a witness (`HashTree`), and an expression path. The witness and expression path is used to generate the `IC-Certificate` header, which is added to the response before returning it.

```rust
fn serve_asset(req: &HttpRequest) -> HttpResponse {
    ASSET_ROUTER.with_borrow(|asset_router| {
        if let Ok((mut response, witness, expr_path)) = asset_router.serve_asset(req) {
            add_certificate_header(&mut response, &witness, &expr_path);

            response
        } else {
            ic_cdk::trap("Failed to serve asset");
        }
    })
}
```

To add the `IC-Certificate` header to the response, the `add_certificate_header` function is used. This function takes the response, witness, and expression path as arguments. The witness, expression path, and the canister's certified data are encoded using CBOR and then added to the response headers.

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
```
