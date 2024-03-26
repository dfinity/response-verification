use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ic_cdk::{
    api::{data_certificate, set_certified_data},
    *,
};
use ic_http_certification::{
    DefaultCelBuilder, DefaultFullCelExpression, DefaultResponseCertification,
    DefaultResponseOnlyCelExpression, HttpCertification, HttpCertificationPath,
    HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest, HttpResponse,
};
use lazy_static::lazy_static;
use matchit::{Params, Router};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::HashMap};

mod types;
use types::*;

// Public methods

// run when a canister is first installed
#[init]
fn init() {
    // prepare reusable CEL expressions
    prepare_cel_exprs();

    // certify all static responses
    certify_list_todos_response();
    certify_not_allowed_todo_responses();
    certify_not_found_response();

    // prepare query and update handlers
    prepare_query_handlers();
    prepare_update_handlers();
}

// run every time a canister is upgraded
#[post_upgrade]
fn post_upgrade() {
    // run the same initialization logic
    init();
}

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    let req_path = req.get_path().expect("Failed to get req path");

    QUERY_ROUTER.with_borrow(|query_router| {
        let method_router = query_router.get(&req.method.to_uppercase()).unwrap();
        let handler_match = method_router.at(&req_path).unwrap();
        let handler = handler_match.value;

        handler(&req, &handler_match.params)
    })
}

#[update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    let req_path = req.get_path().expect("Failed to get req path");

    UPDATE_ROUTER.with_borrow(|update_router| {
        let method_router = update_router.get(&req.method.to_uppercase()).unwrap();
        let handler_match = method_router.at(&req_path).unwrap();
        let handler = handler_match.value;

        handler(&req, &handler_match.params)
    })
}

// Storage

#[derive(Debug, Clone)]
struct CertifiedHttpResponse {
    response: HttpResponse,
    certification: HttpCertification,
}

thread_local! {
    // todo items
    static NEXT_TODO_ID: RefCell<u32> = RefCell::new(0);
    static TODO_ITEMS: RefCell<HashMap<u32, TodoItem>> = RefCell::new(HashMap::new());

    // HTTP certification tree
    static HTTP_TREE: RefCell<HttpCertificationTree> = RefCell::new(HttpCertificationTree::default());

    // responses
    static FALLBACK_RESPONSES: RefCell<HashMap<String, CertifiedHttpResponse>> = RefCell::new(HashMap::new());
    static RESPONSES: RefCell<HashMap<(String, String), CertifiedHttpResponse>> = RefCell::new(HashMap::new());

    // cel expressions
    static RESPONSE_ONLY_CEL_EXPRS: RefCell<HashMap<String, (DefaultResponseOnlyCelExpression<'static>, String)>> = RefCell::new(HashMap::new());
    static FULL_CEL_EXPRS: RefCell<HashMap<String, (DefaultFullCelExpression<'static>, String)>> = RefCell::new(HashMap::new());

    // routers
    static QUERY_ROUTER: RefCell<HashMap<String, Router<RouteHandler>>> = RefCell::new(HashMap::new());
    static UPDATE_ROUTER: RefCell<HashMap<String, Router<RouteHandler>>> = RefCell::new(HashMap::new());
}

const TODOS_PATH: &str = "/todos";
const NOT_FOUND_PATH: &str = "";

lazy_static! {
    static ref TODOS_TREE_PATH: HttpCertificationPath<'static> =
        HttpCertificationPath::exact(TODOS_PATH);
    static ref NOT_FOUND_TREE_PATH: HttpCertificationPath<'static> =
        HttpCertificationPath::wildcard(NOT_FOUND_PATH);
}

// Certification

fn prepare_cel_exprs() {
    // define a full CEL expression that will certify the following:
    // - request
    //   - method
    //   - body
    //   - no headers
    //   - no query parameters
    // - response
    //   - status code
    //   - body
    //   - all headers
    // this CEL expression will be used for all routes except for the not found route
    let cel_expr_def = DefaultCelBuilder::full_certification()
        .with_request_headers(vec![])
        .with_request_query_parameters(vec![])
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build();

    // also pre-compute the stringified CEL expression
    let cel_expr_str = cel_expr_def.to_string();

    // insert the CEL expressions
    FULL_CEL_EXPRS.with_borrow_mut(|exprs| {
        // insert on the `/todos` path
        exprs.insert(
            TODOS_PATH.to_string(),
            (cel_expr_def.clone(), cel_expr_str.clone()),
        );
    });

    // define a response-only CEL expression that will certify the following:
    // - response
    //   - status code
    //   - body
    //   - all headers
    // this CEL expression will be used for the not found route
    let not_found_cel_expr_def = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build();

    // also pre-compute the stringified CEL expression
    let not_found_cel_expr = not_found_cel_expr_def.to_string();

    RESPONSE_ONLY_CEL_EXPRS.with_borrow_mut(|exprs| {
        // insert on the not found path
        exprs.insert(
            NOT_FOUND_PATH.to_string(),
            (not_found_cel_expr_def, not_found_cel_expr),
        );
    });
}

fn certify_list_todos_response() {
    let request = HttpRequest {
        url: TODOS_PATH.to_string(),
        method: "GET".to_string(),
        headers: vec![],
        body: vec![],
    };

    let body = TODO_ITEMS.with_borrow(|items| {
        ListTodosResponse::ok(
            &items
                .iter()
                .map(|(_id, item)| item.clone())
                .collect::<Vec<_>>(),
        )
        .encode()
    });
    let response = create_response(200, body);

    certify_response(request, response, &TODOS_TREE_PATH);
}

fn certify_not_allowed_todo_responses() {
    ["HEAD", "PUT", "PATCH", "OPTIONS", "TRACE", "CONNECT"]
        .iter()
        .for_each(|method| {
            let request = HttpRequest {
                url: TODOS_PATH.to_string(),
                method: method.to_string(),
                headers: vec![],
                body: vec![],
            };

            let body = ErrorResponse::not_allowed().encode();
            let response = create_response(405, body);

            certify_response(request, response, &TODOS_TREE_PATH);
        });
}

fn certify_not_found_response() {
    let body = ErrorResponse::not_found().encode();
    let mut response = create_response(404, body);

    let tree_path = HttpCertificationPath::wildcard(NOT_FOUND_PATH);

    let certification = RESPONSE_ONLY_CEL_EXPRS.with_borrow(|cel_exprs| {
        // get the appropriate CEL expression for the provided request path
        let (cel_expr_def, cel_expr_str) = cel_exprs.get(NOT_FOUND_PATH).unwrap();

        // insert the `Ic-CertificationExpression` header with the stringified CEL expression as its value
        response.headers.push((
            IC_CERTIFICATE_EXPRESSION_HEADER.to_string(),
            cel_expr_str.to_string(),
        ));

        // create the certification for this response and CEL expression pair
        HttpCertification::response_only(&cel_expr_def, &response, None).unwrap()
    });

    FALLBACK_RESPONSES.with_borrow_mut(|responses| {
        responses.insert(
            NOT_FOUND_PATH.to_string(),
            CertifiedHttpResponse {
                response,
                certification,
            },
        );
    });

    HTTP_TREE.with_borrow_mut(|http_tree| {
        // insert the certification into the certification tree
        http_tree.insert(&HttpCertificationTreeEntry::new(tree_path, &certification));

        // set the canister's certified data
        set_certified_data(&http_tree.root_hash());
    });
}

const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";
fn certify_response(
    request: HttpRequest,
    mut response: HttpResponse,
    tree_path: &HttpCertificationPath,
) {
    let request_path = request.get_path().unwrap();

    // retrieve and remove any existing response for the request method and path
    let existing_response = RESPONSES.with_borrow_mut(|responses| {
        responses.remove(&(request.method.clone(), request_path.clone()))
    });

    // if there is an existing response, remove its certification from the certification tree
    if let Some(existing_response) = existing_response {
        HTTP_TREE.with_borrow_mut(|http_tree| {
            http_tree.delete(&HttpCertificationTreeEntry::new(
                tree_path.clone(),
                &existing_response.certification,
            ));
        })
    }

    let certification = FULL_CEL_EXPRS.with_borrow(|cel_exprs| {
        // get the appropriate CEL expression for the provided request path
        let (cel_expr_def, cel_expr_str) = cel_exprs.get(&request_path).unwrap();

        // insert the `Ic-CertificationExpression` header with the stringified CEL expression as its value
        response.headers.push((
            IC_CERTIFICATE_EXPRESSION_HEADER.to_string(),
            cel_expr_str.to_string(),
        ));

        // create the certification for this response and CEL expression pair
        HttpCertification::full(cel_expr_def, &request, &response, None).unwrap()
    });

    RESPONSES.with_borrow_mut(|responses| {
        // store the response for later retrieval
        responses.insert(
            (request.method, request_path),
            CertifiedHttpResponse {
                response: response.clone(),
                certification: certification.clone(),
            },
        );
    });

    HTTP_TREE.with_borrow_mut(|http_tree| {
        // insert the certification into the certification tree
        http_tree.insert(&HttpCertificationTreeEntry::new(tree_path, &certification));

        // set the canister's certified data
        set_certified_data(&http_tree.root_hash());
    });
}

// Handlers

fn prepare_query_handlers() {
    insert_query_route("POST", "/todos", upgrade_to_update_call_handler);
    insert_query_route("PATCH", "/todos/{id}", upgrade_to_update_call_handler);
    insert_query_route("DELETE", "/todos/{id}", upgrade_to_update_call_handler);

    insert_query_route("GET", "/{*p}", query_handler);
    ["HEAD", "PUT", "OPTIONS", "TRACE", "CONNECT"]
        .iter()
        .for_each(|method| {
            insert_query_route(method, "/{*p}", query_handler);
        });
}

fn insert_query_route(method: &str, path: &str, route_handler: RouteHandler) {
    QUERY_ROUTER.with_borrow_mut(|query_router| {
        let router = query_router.entry(method.to_string()).or_default();

        router.insert(path, route_handler).unwrap();
    });
}

fn prepare_update_handlers() {
    insert_update_route("POST", TODOS_PATH, create_todo_item_handler);
    insert_update_route("PATCH", "/todos/{id}", update_todo_item_handler);
    insert_update_route("DELETE", "/todos/{id}", delete_todo_item_handler);

    insert_update_route("GET", "/{*p}", no_update_call_handler);
    ["HEAD", "PUT", "OPTIONS", "TRACE", "CONNECT"]
        .iter()
        .for_each(|method| {
            insert_update_route(method, "/{*p}", no_update_call_handler);
        });
}

fn insert_update_route(method: &str, path: &str, route_handler: RouteHandler) {
    UPDATE_ROUTER.with_borrow_mut(|update_router| {
        let router = update_router.entry(method.to_string()).or_default();

        router.insert(path, route_handler).unwrap();
    });
}

fn query_handler(request: &HttpRequest, _params: &Params) -> HttpResponse {
    let request_path = request.get_path().expect("Failed to get req path");

    // first check if there is a certified response for the request method and path
    let (tree_path, certified_response) = RESPONSES
        .with_borrow(|responses| {
            responses
                .get(&(request.method.clone(), request_path.clone()))
                .map(|response| {
                    (
                        HttpCertificationPath::exact(&request_path),
                        response.clone(),
                    )
                })
        })
        // if there is no certified response, use the fallback response
        .unwrap_or_else(|| {
            FALLBACK_RESPONSES.with_borrow(|fallback_responses| {
                fallback_responses
                    .get(NOT_FOUND_PATH)
                    .clone()
                    .map(|response| (NOT_FOUND_TREE_PATH.to_owned(), response.clone()))
                    .unwrap()
            })
        });

    let mut response = certified_response.response;

    add_certificate_header(
        &mut response,
        &HttpCertificationTreeEntry::new(&tree_path, certified_response.certification),
        &request_path,
        &tree_path.to_expr_path(),
    );

    response
}

fn create_todo_item_handler(req: &HttpRequest, _params: &Params) -> HttpResponse {
    let req_body: CreateTodoItemRequest = json_decode(&req.body);

    let id = NEXT_TODO_ID.with_borrow_mut(|f| {
        let id = *f;
        *f += 1;
        id
    });

    let todo_item = TODO_ITEMS.with_borrow_mut(|items| {
        let todo_item = TodoItem {
            id,
            title: req_body.title,
            completed: false,
        };

        items.insert(id, todo_item.clone());

        todo_item
    });

    certify_list_todos_response();

    let body = CreateTodoItemResponse::ok(&todo_item).encode();
    create_response(201, body)
}

fn update_todo_item_handler(req: &HttpRequest, params: &Params) -> HttpResponse {
    let req_body: UpdateTodoItemRequest = json_decode(&req.body);
    let id: u32 = params.get("id").unwrap().parse().unwrap();

    TODO_ITEMS.with_borrow_mut(|items| {
        let item = items.get_mut(&id).unwrap();

        if let Some(title) = req_body.title {
            item.title = title;
        }

        if let Some(completed) = req_body.completed {
            item.completed = completed;
        }
    });

    certify_list_todos_response();

    let body = UpdateTodoItemResponse::ok(&()).encode();
    create_response(200, body)
}

fn delete_todo_item_handler(_req: &HttpRequest, params: &Params) -> HttpResponse {
    let id: u32 = params.get("id").unwrap().parse().unwrap();

    TODO_ITEMS.with_borrow_mut(|items| {
        items.remove(&id);
    });

    certify_list_todos_response();

    let body = DeleteTodoItemResponse::ok(&()).encode();
    create_response(204, body)
}

fn upgrade_to_update_call_handler(_http_request: &HttpRequest, _params: &Params) -> HttpResponse {
    HttpResponse {
        status_code: 200,
        headers: vec![],
        body: vec![],
        upgrade: Some(true),
    }
}

fn no_update_call_handler(_http_request: &HttpRequest, _params: &Params) -> HttpResponse {
    create_response(400, vec![])
}

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
    let witness = HTTP_TREE.with_borrow(|http_tree| {
        let witness = http_tree.witness(entry, request_url).unwrap();
        cbor_encode(&witness)
    });

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

fn json_decode<T>(value: &[u8]) -> T
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(value).expect("Failed to deserialize value")
}

fn create_response(status_code: u16, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status_code,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "strict-transport-security".to_string(),
                "max-age=31536000; includeSubDomains".to_string(),
            ),
            ("x-content-type-options".to_string(), "nosniff".to_string()),
            ("referrer-policy".to_string(), "no-referrer".to_string()),
            (
                "cache-control".to_string(),
                "no-store, max-age=0".to_string(),
            ),
            ("pragma".to_string(), "no-cache".to_string()),
        ],
        body,
        upgrade: None,
    }
}
