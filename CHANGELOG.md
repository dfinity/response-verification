## Unreleased

### Feat

- add cel to ast parser
- add current time and max cert time offset as parameters
- add certificate time check
- **hashing**: added (probably incorrect) R-I hashing implementation
- **hashing**: new crate
- **cel-parser**: new crate
- add type-safe exception for JS clients
- add initial response verification logic
- add initial response verification logic
- add cbor parsing of certificate and tree
- **response-verification**: add initial request, response interface
- **certificate-header**: add certificate header handling (#5)

### Refactor

- use From trait for error conversion instead of Into
- migrate wasm-bindgen to bazel toolchain rules format and refactor binaryen to match
- create reusable function for body decoding
- remove redundant if statement and merge with match statement
- replace let match statements with let else statements
- improved error handling
- use nom to parse header field instead of regex
- rename pub interface function for JS to verify_request_response_pair
- remove `serde` in favor of `js-sys`

### Perf

- add binaryen wasm opt support

## 0.0.0 (2022-09-29)
