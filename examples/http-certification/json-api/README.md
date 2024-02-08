# Serving JSON over HTTP

## Overview

This guide walks through an example project that demonstrates how to create a canister that can serve certified JSON over HTTP. The example project presents a very simple REST API for creating and listing to-do items. There is no authentication or persistent storage.

:::caution
This is not a beginner's canister development guide. Many foundational concepts that a relatively experienced canister developer should already know will be omitted. Concepts specific to HTTP certification will be called out here and can help to understand the [full code example](https://github.com/dfinity/response-verification/tree/main/examples/http-certification/json-api).
:::

## Prerequisites

It's recommended to check out earlier guides before reading this one. The JSON API example in particular will be referenced.

- [x] Complete the ["Custom HTTP canisters"](https://internetcomputer.org/docs/current/developer-docs/http-compatible-canisters/custom-http-canisters) guide.

## Lifecycle

In the `init` lifecycle hook, the CEL expressions are prepared and responses are certified. The same function runs during the `post_upgrade` hook since the certified structure is not persisted across upgrades.

```rust
#[init]
fn init() {
    prepare_cel_exprs();
    certify_list_todos_response();
    certify_not_found_response();
}

#[post_upgrade]
fn post_upgrade() {
    init();
}
```

## CEL expressions

CEL expressions only need to be setup once and can then be reused until the next canister upgrade. Responses can also be setup once and reused. If the response is static and will not change throughout the canister's lifetime, then it only needs to be certified once. If the response can change however, then it will need to be re-certified every time it changes.

To store CEL expressions, a `HashMap` is created:

```rust
thread_local! {
    static CEL_EXPRS: RefCell<HashMap<String, (DefaultResponseOnlyCelExpression<'static>, String)>> = RefCell::new(HashMap::new());
}
```

The `HashMap` uses the request path as the key, and a tuple of `(DefaultResponseOnlyCelExpression, String)` as the value. `DefaultResponseOnlyCelExpression` is a parsed CEL expression definition and `String` is the stringified version of it.

`DefaultResponseOnlyCelExpression` is used when only the response is to be certified. If the request is also to be certified, then `DefaultFullCelExpression` should be used. Separate `HashMap`s could be created to hold different types of CEL expressions, or the higher level `DefaultCelExpression` can hold any type of CEL expression using the "Default" scheme. In the future there may be more schemes, and the higher level `CelExpression` can hold CEL expressions from different schemes. It is up to the developers to decide how they want to store and organize their CEL expressions.

:::info 
In this example, there is only one CEL expression used. This CEL expression is cloned and used for both request paths that are being certified. For more information on defining CEL expressions, see the relevant section in the [`ic-http-certification` docs](https://docs.rs/ic-http-certification/latest/ic_http_certification/#defining-cel-expressions).
:::

```rust
const TODOS_PATH: &str = "todos";
const NOT_FOUND_PATH: &str = "";

fn prepare_cel_exprs() {
    // define a response-only CEL expression that will certify the response status code and body (they are included by default) and the `content-type` response header.
    let cel_expr_def = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::certified_response_headers(&[
            "content-type",
        ]))
        .build();

    // also pre-compute the stringified CEL expression
    let cel_expr_str = cel_expr_def.to_string();

    // insert the CEL expressions
    CEL_EXPRS.with_borrow_mut(|exprs| {
        // insert on the `/todos` path
        exprs.insert(
            TODOS_PATH.to_string(),
            (cel_expr_def.clone(), cel_expr_str.clone()),
        );

        // insert for the not found path
        exprs.insert(NOT_FOUND_PATH.to_string(), (cel_expr_def, cel_expr_str));
    });
}
```

## Responses

The certification tree has its own dedicated data structure while responses, similarly to CEL expressions, are stored in a `HashMap`, along with their respective certifications. The responses and certifications are stored separately from the CEL expressions because they are likely to change throughout the canister's lifecycle, where as the CEL expressions are set once. They could all be stored within the same structure if a developer wishes.

```rust
struct CertifiedHttpResponse {
    response: HttpResponse,
    certification: HttpCertification,
}

thread_local! {
    static RESPONSES: RefCell<HashMap<String, CertifiedHttpResponse>> = RefCell::new(HashMap::new());
    static HTTP_TREE: RefCell<HttpCertificationTree> = RefCell::new(HttpCertificationTree::default());
}
```

Responses are certified with a number of steps, which are encapsulated into a reusable function:

- Retrieve the pre-computed CEL expression for the request path.
- Insert the `Ic-CertificationExpression` header for the given response, with the corresponding stringified CEL expression as its value.
- Calculate the certification for the given response and CEL expression.
- Store the response together with its certification.
- Insert the certification into the certification tree at the appropriate path.
- Update the canister's [certified data](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-certified-data).

For more information on creating certifications, see the relevant section in the [`ic-http-certification` docs](https://docs.rs/ic-http-certification/latest/ic_http_certification/#creating-certifications).

```rust
const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";
fn certify_response(
    mut response: HttpResponse,
    tree_path: HttpCertificationPath,
    request_path: String,
) {
    let certification = CEL_EXPRS.with_borrow(|cel_exprs| {
        // get the appropriate CEL expression for the provided request path
        let (cel_expr_def, cel_expr_str) = cel_exprs.get(&request_path).unwrap();

        // insert the `Ic-CertificationExpression` header with the stringified CEL expression as its value
        response.headers.push((
            IC_CERTIFICATE_EXPRESSION_HEADER.to_string(),
            cel_expr_str.to_string(),
        ));

        // create the certification for this response and CEL expression pair
        HttpCertification::response_only(cel_expr_def, &response, None)
    });

    RESPONSES.with_borrow_mut(|responses| {
        // store the response for later retrieval
        responses.insert(
            request_path,
            CertifiedHttpResponse {
                response: response.clone(),
                certification: certification.clone(),
            },
        );
    });

    HTTP_TREE.with_borrow_mut(|http_tree| {
        // insert the certification into the certification tree
        http_tree.insert(&HttpCertificationTreeEntry {
            path: &tree_path,
            certification: &certification,
        });

        // set the canister's certified data
        set_certified_data(&http_tree.root_hash());
    });
}
```

These steps can now be re-used for each response that needs to be certified:

```rust
fn certify_list_todos_response() {
    let body = TODO_ITEMS.with_borrow(|items| json_encode(items));

    let response = HttpResponse {
        status_code: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body,
        upgrade: None,
    };

    certify_response(response, TODOS_TREE_PATH, TODOS_PATH.to_string());
}

fn certify_not_found_response() {
    let response = HttpResponse {
        status_code: 404,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: b"Not found".to_vec(),
        upgrade: None,
    };

    certify_response(response, NOT_FOUND_TREE_PATH, NOT_FOUND_PATH.to_string());
}
```

## Serving responses

When serving a certified response, an additional header must be added to the response that will act as a proof of certification for the [HTTP gateway](https://internetcomputer.org/docs/current/references/http-gateway-protocol-spec) that will perform validation. Adding this header to the response has been abstracted into its own function:

```rust
const IC_CERTIFICATE_HEADER: &str = "IC-Certificate";
fn add_certificate_header(
    response: &mut HttpResponse,
    entry: &HttpCertificationTreeEntry,
    request_url: &str,
    expr_path: &[String],
) {
    // get the current certified data of the canister, note that this will not be available in update calls
    let certified_data = data_certificate().expect("No data certificate available");

    // generate a witness for the certification entry and current request URL
    let witness =
        HTTP_TREE.with_borrow(|http_tree| cbor_encode(&http_tree.witness(entry, request_url)));

    // encode the path in the tree that holds the certification
    let expr_path = cbor_encode(&expr_path);

    // create the header value and insert it into the response
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
```

With this reusable function, serving certified responses is relatively straightforward.

```rust
fn list_todo_items_handler(req: &HttpRequest) -> HttpResponse {
    let req_path = req.get_path().expect("Failed to get req path");

    RESPONSES.with_borrow(|responses| {
        let CertifiedHttpResponse {
            certification,
            response,
        } = responses
            .get(TODOS_PATH)
            .expect("No certified response for /todos");
        let mut response = response.clone();

        add_certificate_header(
            &mut response,
            &HttpCertificationTreeEntry {
                path: &TODOS_TREE_PATH,
                certification: &certification,
            },
            &req_path,
            &TODOS_TREE_PATH.to_expr_path(),
        );

        response
    })
}

fn not_found_handler(req: &HttpRequest) -> HttpResponse {
    let req_path = req.get_path().expect("Failed to get req path");

    RESPONSES.with_borrow(|responses| {
        let CertifiedHttpResponse {
            certification,
            response,
        } = responses
            .get(NOT_FOUND_PATH)
            .expect("No certified response for not found");
        let mut response = response.clone();

        add_certificate_header(
            &mut response,
            &HttpCertificationTreeEntry {
                path: &NOT_FOUND_TREE_PATH,
                certification: &certification,
            },
            &req_path,
            &NOT_FOUND_TREE_PATH.to_expr_path(),
        );

        response
    })
}
```

## Updating state

The to-do list is updatable via `POST` requests. These calls will initially be received as [`query` calls](https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-query), so we'll need to [upgrade to an update call](https://internetcomputer.org/docs/current/references/http-gateway-protocol-spec#upgrade-to-update-calls) to allow for the canister's state to change.

```rust
fn upgrade_to_update_call_handler() -> HttpResponse {
    HttpResponse {
        status_code: 200,
        headers: vec![],
        body: vec![],
        upgrade: Some(true),
    }
}
```

This will tell the HTTP gateway to remake the request as an [`update` call](https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-call). Since it's an update call, the response to this request does not need to be certified. We will, however, need to re-certify the to-do list response. We can reuse the same `certify_list_todos_response` from above to achieve this.

```rust
fn create_todo_item_handler(req: &HttpRequest) -> HttpResponse {
    let req_body: CreateTodoItemRequest = json_decode(&req.body);

    let id = NEXT_TODO_ID.with_borrow_mut(|f| {
        let id = *f;
        *f += 1;
        id
    });

    let todo_item = TODO_ITEMS.with_borrow_mut(|items| {
        let todo_item = TodoItem {
            id,
            text: req_body.text,
            completed: false,
        };

        items.push(todo_item.clone());

        todo_item
    });

    certify_list_todos_response();

    HttpResponse {
        status_code: 201,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: json_encode(&todo_item),
        upgrade: None,
    }
}
```

## Resources

- [Example source code](https://github.com/dfinity/response-verification/tree/main/examples/http-certification/json-api).
- [`ic-http-certification` crate](https://crates.io/crates/ic-http-certification).
- [`ic-http-certification` docs](https://docs.rs/ic-http-certification/latest/ic_http_certification).
- [`ic-http-certification` source code](https://github.com/dfinity/response-verification/tree/main/packages/ic-http-certification).
