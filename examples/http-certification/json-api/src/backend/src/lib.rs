use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ic_cdk::{
    api::{data_certificate, set_certified_data},
    *,
};
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, DefaultResponseOnlyCelExpression,
    HttpCertification, HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry,
    HttpRequest, HttpResponse,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::HashMap};

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

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    let path = req.get_path().expect("Failed to get req path");

    match path.as_str() {
        "/todos" => match req.method.as_str() {
            "GET" => list_todo_items_handler(&req),
            "POST" => upgrade_to_update_call_handler(),
            _ => not_found_handler(&req),
        },
        _ => not_found_handler(&req),
    }
}

#[update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    let path = req.get_path().expect("Failed to get req path");

    match path.as_str() {
        "/todos" => match req.method.as_str() {
            "GET" => list_todo_items_handler(&req),
            "POST" => create_todo_item_handler(&req),
            _ => not_found_handler(&req),
        },
        _ => not_found_handler(&req),
    }
}

struct CertifiedHttpResponse {
    response: HttpResponse,
    certification: HttpCertification,
}

thread_local! {
    static TODO_ITEMS: RefCell<Vec<TodoItem>> = RefCell::new(Vec::new());
    static NEXT_TODO_ID: RefCell<u32> = RefCell::new(0);

    static HTTP_TREE: RefCell<HttpCertificationTree> = RefCell::new(HttpCertificationTree::default());
    static RESPONSES: RefCell<HashMap<String, CertifiedHttpResponse>> = RefCell::new(HashMap::new());
    static CEL_EXPRS: RefCell<HashMap<String, (DefaultResponseOnlyCelExpression<'static>, String)>> = RefCell::new(HashMap::new());
}

const TODOS_PATH: &str = "todos";
const TODOS_TREE_PATH: HttpCertificationPath = HttpCertificationPath::Exact(TODOS_PATH);

const NOT_FOUND_PATH: &str = "";
const NOT_FOUND_TREE_PATH: HttpCertificationPath = HttpCertificationPath::Wildcard(NOT_FOUND_PATH);

#[derive(Debug, Clone, Serialize)]
struct TodoItem {
    id: u32,
    text: String,
    completed: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct CreateTodoItemRequest {
    text: String,
}

// Certification

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
        http_tree.insert(&HttpCertificationTreeEntry::new(&tree_path, &certification));

        // set the canister's certified data
        set_certified_data(&http_tree.root_hash());
    });
}

// Handlers

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
            &HttpCertificationTreeEntry::new(&TODOS_TREE_PATH, &certification),
            &req_path,
            &TODOS_TREE_PATH.to_expr_path(),
        );

        response
    })
}

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
            &HttpCertificationTreeEntry::new(&NOT_FOUND_TREE_PATH, &certification),
            &req_path,
            &NOT_FOUND_TREE_PATH.to_expr_path(),
        );

        response
    })
}

fn upgrade_to_update_call_handler() -> HttpResponse {
    HttpResponse {
        status_code: 200,
        headers: vec![],
        body: vec![],
        upgrade: Some(true),
    }
}

// Utilities

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

fn json_encode(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("Failed to serialize value")
}

fn json_decode<T>(value: &[u8]) -> T
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(value).expect("Failed to deserialize value")
}
