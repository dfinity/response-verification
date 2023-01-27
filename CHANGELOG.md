## Unreleased

### Feat

- use filter_response_headers function to return certified headers
- check for more precise expr_path matches in the tree
- filter and return response headers based on certificate expression
- verify request & response hashes in tree
- Verify ic certificate with root public key
- add expr_path check
- integrate request and response hash functions
- integrate cel parser with response verification entry point
- returns the decoded response body to the client
- envelope request verification adding the certified response
- create separate function for response header hashing
- conditionally execute v1 response verification
- extract version and expr_path from IC certificate header
- extract version and expr_path from IC certificate header
- add request hash
- add response hash implementation
- add support for numbers in representation independent hash
- add representation indepdendant hash
- add CEL ast to certification object validation and mapping
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

### Fix

- validate against encoded and decoded body sha
- hash encoded body for v2 response verification instead of decoded body
- fixes cargo lock duplicate entry for ic-certification
- representation independant hash should allow for duplicate keys

### Refactor

- move certificate verification logic to acommodate for code split
- remove debug log used for rust examples
- use miracl_core_bls12381 crate for bls verification to reduce wasm size
- remove unnecessary dfx.json config
- update project structure
- move verification version check to its own function
- make default path const
- add more realistic test data
- early return for filtered headers and certificate expression header
- make response status pseudo header name const
- update response hash to use number for status code encoding
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
