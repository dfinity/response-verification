use ic_response_verification::parse_certificate_header;

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
    let certificate_header = parse_certificate_header(header);

    println!("Certificate header: {:?}", certificate_header);
}
