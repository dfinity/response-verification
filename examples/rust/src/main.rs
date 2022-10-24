use ic_response_verification::{
    request::Request, response::Response, verify_request_response_pair,
};

fn create_header_field(name: &str, value: &str) -> String {
    let base64_value = base64::encode(value);

    format!("{}=:{}:", name, base64_value)
}

fn main() {
    let header = vec![
        create_header_field("certificate", "Hello Certificate!"),
        create_header_field("tree", "Hello Tree!"),
    ]
    .join(",");
    let request = Request {
        headers: vec![(String::from("Ic-Certificate"), header.clone())],
    };
    let response = Response {
        headers: vec![(String::from("Ic-Certificate"), header.clone())],
    };
    let certificate_header = verify_request_response_pair(request, response);

    println!("Certificate header: {:?}", certificate_header);
}
