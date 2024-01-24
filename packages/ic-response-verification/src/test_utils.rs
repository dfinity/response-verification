use ic_certification::hash_tree::{fork, label, leaf, pruned_from_hex, Hash};
use ic_certification::HashTree;
use ic_response_verification_test_utils::{base64_encode, hex_decode};

pub struct CreateTreeOptions<'a> {
    pub path: Option<&'a str>,
    pub body_sha: Option<&'a [u8]>,
}

pub fn create_tree(options: Option<CreateTreeOptions>) -> HashTree {
    const DEFAULT_PATH: &str = "/";
    let path = options
        .as_ref()
        .and_then(|options| options.path)
        .unwrap_or(DEFAULT_PATH);

    let default_body_sha =
        hex_decode("784C0F825A938AA7F471587CDF7C7796F828F9362495E2B9C8490F2232359BDB");
    let body_sha = options
        .as_ref()
        .and_then(|options| options.body_sha)
        .unwrap_or(&default_body_sha);

    fork(
        label(
            "http_assets",
            fork(
                fork(
                    label(path, leaf(body_sha)),
                    create_pruned(
                        "D7CD0A6CF52A2070DC51FE1D7B6A87078888719E16849C748C35E7FC7B69F95C",
                    ),
                ),
                create_pruned("582B5321336646D48C6F8BF1913333BB4EBF65C09FFBF8207C012E1F54071261"),
            ),
        ),
        create_pruned("21334B26681D7220E3D2D7DCB23A89CCDB1B1E044EB35EBBE491F66D4080D078"),
    )
}

pub fn create_pruned(data: &str) -> HashTree {
    pruned_from_hex(data).unwrap()
}

pub fn sha256_from_hex(data: &str) -> Hash {
    TryFrom::try_from(hex_decode(data)).unwrap()
}

pub fn create_encoded_header_field<T: AsRef<[u8]>>(name: &str, value: T) -> String {
    let value = base64_encode(value.as_ref());

    create_header_field(name, &value)
}

pub fn create_header_field(name: &str, value: &str) -> String {
    format!("{}=:{}:", name, value)
}

pub fn remove_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}
