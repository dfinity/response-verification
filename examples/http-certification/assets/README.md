# HTTP Certified Assets

This example project demonstrates how to create a very simple HTTP Certified Asset Canister for serving a single page JavaScript application. Assets are embeeded into the canister at compile time.

This guide is not a canister development guide so it will omit or gloss over concepts that a relatively experienced canister developer will already know. Concepts specific to HTTP Certification will be called out here and can help to understand the full code example.

It's recommended to check out the simpler, [JSON API example](../json-api/README.md) before checking this example. The JSON API example will also be referenced here to not explain similar things again.

## The Frontend Assets

The frontend project used for this example is a simple starter project generated with ` npx degit solidjs/templates/ts my-app`. The only changes that have been made are in the `vite.config.ts` file. The `vite-plugin-compression` plugin was added and configured to generate Gzip and Brotli encoded assets, alongside the original assets. The `ext` configuration affects the file extension and it's important to keep this consistent with the backend canister code that we'll see later.

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

Now, we can look at the canister code.

## Lifecycle

The lifecycle hooks are setup in a similar fashion to the JSON API.

```rust
#[init]
fn init() {
    prepare_cel_exprs();
    certify_all_assets();
}

#[post_upgrade]
fn post_upgrade() {
    init();
}
```

## CEL Expressions

CEL expressions are also stored similarly to the JSON API.

```rust
thread_local! {
    static CEL_EXPRS: RefCell<HashMap<String, (DefaultResponseOnlyCelExpression<'static>, String)>> = RefCell::new(HashMap::new());
}
```

The CEL expression definition is slightly more complex in the case of assets. The same CEL expression is used for every asset, but a number of addtiaional headers are certified here, namely:

- `content-type` represents the type of content, such as HTML, CSS, JS etc...
- `content-length` represents the byte length of the content.
- `content-encoding` represents the compression algorithm used, such as `identity`, `gzip` or `br` (Brotli).
- `cache-control` used to tell browsers how to cache (or not) the assets.

```rust
fn prepare_cel_exprs() {
    let asset_cel_expr_def = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::certified_response_headers(&[
            "content-type",
            "content-length",
            "content-encoding",
            "cache-control",
        ]))
        .build();

    let asset_cel_expr = asset_cel_expr_def.to_string();

    CEL_EXPRS.with_borrow_mut(|exprs| {
        exprs.insert(
            ASSET_CEL_EXPR_PATH.to_string(),
            (asset_cel_expr_def, asset_cel_expr),
        );
    });
}
```

## Assets

Assets are embedded into the canister's WASM at build time. This is achieved using the [`include_dir`](https://michael-f-bryan.github.io/include_dir/include_dir/index.html) crate. Note that this works fine for a small number of assets, but a larger number of assets may cause longer compile times, as mentioned in the crate's [docs](https://michael-f-bryan.github.io/include_dir/include_dir/index.html#compile-time-considerations).

The assets are imported from the frontend build directory:

```rust
static ASSETS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../frontend/dist");
```

With the assets loaded, similar to the JSON API, we need somewhere to store the pre-calculated responses and certifications. Here we use a slightly different structure. Instead of storing the `HttpResponse`, we store a custom type `HttpAssetResponse`. The only difference with the original `HttpResponse` is that we hold a reference to a `u8` slice. If we used the original `HttpResponse` here, we would essentially duplicate the original asset content by cloning it and storing it in the `RESPONSE`s `HashMap`. [`Cow`](https://doc.rust-lang.org/std/borrow/enum.Cow.html) is also used here for flexibility, in case there is any scenario where we do not have a static reference to data. There is no such scenario in this example however.

```rust
#[derive(Debug, Clone)]
struct HttpAssetResponse<'a> {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: Cow<'a, [u8]>,
}

impl Into<HttpResponse> for HttpAssetResponse<'_> {
    fn into(self) -> HttpResponse {
        HttpResponse {
            status_code: self.status_code,
            headers: self.headers,
            body: self.body.to_vec(),
            upgrade: None,
        }
    }
}

struct CertifiedHttpResponse<'a> {
    response: HttpAssetResponse<'a>,
    certification: HttpCertification,
}

thread_local! {
    static RESPONSES: RefCell<HashMap<String, CertifiedHttpResponse<'static>>> = RefCell::new(HashMap::new());
}
```

Certifying responses is more involved here compared to the simpler approach used in the JSON API. There are a number of paths used in the following functions that warrant some explanation:

- `asset_tree_path`: this is the `HttpCertificationPath` that will be used to store the asset in the tree, for example `HttpCertificationPath::exact("/assets/app.js")`.
- `asset_file_path`: this is the relative file path of the asset on disk prior to being imported into the canister, for example `assets/app.js`.
- `asset_req_path`: this is the absolute path that will be used to request the asset `/assets/app.js`.

The first function to look at is a reusable function that can certify any asset. It sets up the `content-length` header, we'll need more headers than that but they're setup in other functions which we'll see in a moment. Note that when we create the certification we convert `HttpAssetResponse` into `HttpResponse`, which will temporarily clone the entire asset body, but this will be dropped.

```rust
const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";
fn certify_asset_response(
    body: &'static [u8],
    additional_headers: Vec<HeaderField>,
    asset_tree_path: HttpCertificationPath,
    asset_req_path: String,
) {
    CEL_EXPRS.with_borrow(|cel_exprs| {
        // get the relevant CEL expression
        let (cel_expr_def, cel_expr_str) = cel_exprs.get(ASSET_CEL_EXPR_PATH).unwrap();

        // set up our default headers and include additional headers provided by the caller
        let mut headers = vec![
            ("content-length".to_string(), body.len().to_string()),
            (
                IC_CERTIFICATE_EXPRESSION_HEADER.to_string(),
                cel_expr_str.to_string(),
            ),
        ];
        headers.extend(additional_headers);

        // create the response
        let response = HttpAssetResponse {
            status_code: 200,
            headers,
            body: Cow::Borrowed(body),
        };

        // certify the response
        let certification =
            HttpCertification::response_only(cel_expr_def, &response.clone().into(), None);

        RESPONSES.with_borrow_mut(|responses| {
            // store the response for later retrieval
            responses.insert(
                asset_req_path,
                CertifiedHttpResponse {
                    response,
                    certification: certification.clone(),
                },
            );
        });

        HTTP_TREE.with_borrow_mut(|http_tree| {
            // add the certification to the certification tree
            http_tree.insert(&HttpCertificationTreeEntry {
                path: &asset_tree_path,
                certification: &certification,
            });

            // set the canister's certified data
            set_certified_data(&http_tree.root_hash());
        });
    });
}
```

Next we have another reusable function that builds upon the previous function to certify an asset with an encoding. This function will check for a file with an additional file extension matching the requested encoding. For exmaple, if you want to certify `index.html` with `gzip` encoding then it will check for `index.html.gzip` in the previously included asset directory. If the encoded asset exists, then it is certified using the previously defined `certify_asset_response` function.

```rust
fn certify_asset_with_encoding(
    asset_file_path: &str,
    asset_tree_path: HttpCertificationPath,
    asset_req_path: String,
    encoding: &str,
    additional_headers: Vec<HeaderField>,
) {
    // check if the file exists before certifying it
    if let Some(file) = ASSETS_DIR.get_file(format!("{}.{}", asset_file_path, encoding)) {
        let body = file.contents();
        // add the content encoding header
        let mut headers = vec![("content-encoding".to_string(), encoding.to_string())];
        headers.extend(additional_headers);

        certify_asset_response(
            body,
            headers,
            asset_tree_path,
            format!("{}.{}", asset_req_path, encoding),
        );
    };
}
```

Next we have another simple function that will certify an asset for all encodings: Identity, Gzip and Brotli. This function leverages the `certify_asset_response` for the Identity encoding and `certify_asset_with_encoding` for the other encodings:

```rust
fn certify_asset(
    body: &'static [u8],
    asset_file_path: String,
    asset_tree_path: HttpCertificationPath,
    asset_req_path: String,
    additional_headers: Vec<HeaderField>,
) {
    certify_asset_response(
        body,
        additional_headers.clone(),
        asset_tree_path,
        asset_req_path.to_string(),
    );
    certify_asset_with_encoding(
        &asset_file_path,
        asset_tree_path,
        asset_req_path.to_string(),
        "gzip",
        additional_headers.clone(),
    );
    certify_asset_with_encoding(
        &asset_file_path,
        asset_tree_path,
        asset_req_path.to_string(),
        "br",
        additional_headers,
    );
}
```

Next we have a slightly more complex function that will certify a range of assets that match a glob, for example `assets/**/*.js`, with an encoding, for example `text/javascript`:

```rust
fn certify_asset_glob(glob: &str, content_type: &str) {
    // iterate over every asset matching the globa
    for identity_file in ASSETS_DIR
        .find(glob)
        .unwrap()
        .map(|entry| entry.as_file().unwrap())
    {
        // compute the different paths we need for this asset
        let asset_file_path = identity_file.path().to_str().unwrap().to_string();
        let asset_req_path = if !asset_file_path.starts_with("/") {
            format!("/{}", asset_file_path)
        } else {
            asset_file_path.clone()
        };
        let asset_tree_path = HttpCertificationPath::Exact(&asset_req_path);

        // add the content-type and cache-control headers
        let additional_headers = vec![
            ("content-type".to_string(), content_type.to_string()),
            (
                "cache-control".to_string(),
                "public, max-age=31536000, immutable".to_string(),
            ),
        ];

        let body = identity_file.contents();
        certify_asset(
            body,
            asset_file_path.to_string(),
            asset_tree_path,
            asset_req_path.to_string(),
            additional_headers,
        );
    }
}
```

And finally, we have a function to certify the `index.html` file. Since this is a single page application, we want any requests that don't match an existing file to fallback to `index.html` so we need to handle the certification differently.

```rust
const INDEX_REQ_PATH: &str = "";
const INDEX_TREE_PATH: HttpCertificationPath = HttpCertificationPath::Wildcard(INDEX_REQ_PATH);
const INDEX_FILE_PATH: &str = "index.html";

fn certify_index_asset() {
    let additional_headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        (
            "cache-control".to_string(),
            "public, no-cache, no-store".to_string(),
        ),
    ];

    let identity_file = ASSETS_DIR
        .get_file(INDEX_FILE_PATH)
        .expect("No index.html file found!!!");
    let body = identity_file.contents();

    certify_asset(
        body,
        INDEX_FILE_PATH.to_string(),
        INDEX_TREE_PATH,
        INDEX_REQ_PATH.to_string(),
        additional_headers,
    );
}
```

And with all of the above functions we can certify all of our assets:

```rust
fn certify_all_assets() {
    certify_index_asset();
    certify_asset_glob("assets/**/*.css", "text/css");
    certify_asset_glob("assets/**/*.js", "text/javascript");
    certify_asset_glob("assets/**/*.ico", "image/x-icon");
    certify_asset_glob("assets/**/*.svg", "image/svg+xml");
}
```

## Serving assets

There's just one final piece to the puzzle now, and that's serving assets. The steps to follow here are:

- Check if the requested path matches a file (ex. `/assets/app.js`)
  - If it matches a file serve that file
  - Otherwise serve the `index.html` file
- Extract the request content encoding header
  - Serve the Brotli encoded asset if it was requested and we have it
  - Otherwise, serve the Gzip encoded asset if it was requested and we have it
  - Otherwise, serve the original asset
- Add the certificate header, this is the same process as with the JSON API.

```rust
fn asset_handler(req: &HttpRequest) -> HttpResponse {
    let req_path = req.get_path().expect("Failed to get req path");

    RESPONSES.with_borrow(|responses| {
        let (asset_req_path, asset_tree_path, identity_response) =
            // if the requested path matches a static asset, serve that
            if let Some(identity_response) = responses.get(&req_path) {
                (
                    req_path.to_string(),
                    HttpCertificationPath::Exact(&req_path),
                    identity_response,
                )
            // otherwise serve the index.html
            } else {
                (
                    INDEX_REQ_PATH.to_string(),
                    INDEX_TREE_PATH,
                    responses.get(INDEX_REQ_PATH).unwrap(),
                )
            };

        // extract the content encoding header
        let content_encoding = req.headers.iter().find_map(|(name, value)| {
            if name.to_lowercase() == "accept-encoding" {
                Some(value)
            } else {
                None
            }
        });

        let CertifiedHttpResponse {
            certification,
            response,
        } = content_encoding
            .and_then(|encoding| {
                // if the request asks for Brotli and it's available for this file, serve that version
                if encoding.contains("br") {
                    ic_cdk::println!("{}.br", asset_req_path);
                    if let Some(br_response) = responses.get(&format!("{}.br", asset_req_path)) {
                        return Some(br_response);
                    }
                }

                // if the request asks for Gzip and it's available for this file, serve that version
                if encoding.contains("gzip") {
                    if let Some(gzip_response) = responses.get(&format!("{}.gzip", asset_req_path))
                    {
                        return Some(gzip_response);
                    }
                }

                None
            })
            // otherwise serve the identity version
            .unwrap_or(identity_response);

        let mut response: HttpResponse = response.clone().into();

        add_certificate_header(
            &mut response,
            &HttpCertificationTreeEntry {
                path: &asset_tree_path,
                certification: &certification,
            },
            &req_path,
            &asset_tree_path.to_expr_path(),
        );

        response
    })
}
```

This function can then be simply linked up to our `http_request` handler:

```rust
#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    asset_handler(&req)
}
```
