## Unreleased

### Feat

- **ic-asset-certification**: add support for asset redirection
- **ic-asset-certification**: add alias support to asset router
- **ic-asset-certification**: add support for multiple fallbacks per asset
- **ic-asset-certification**: optionally init asset router with HTTP Certification tree
- **ic-asset-certification**: add initial asset router

### Fix

- **ic-http-certification**: ensure all possible wildcards are witnessed
- **ic-certification**: remove empty subtrees after removing nodes on a path
- **ic-http-certification**: fixed an issue where an asset that has a wildcard but not an exact path is not witnessed correctly
- **ic-certificate-verification**: redundant dependency

## 2.5.0 (2024-03-19)

### Feat

- **ic-http-certification**: add certificate expression header validation
- **certificate-verification-js**: update agent-js and associated packages to v1.0.1
- **ic-certificate-verification**: consolidate certification time check into overall cerificate verification check
- add support for hashing arrays of Value-objects

### Fix

- **ic-http-certification**: incorrect witness generation
- **ic-http-certification**: only calculate response body hash when necessary
- clippy

## 2.4.0 (2024-02-19)

### Feat

- hide enums from interfaces that provide factories/constructors
- **ic-http-certification**: add HttpCertificationTree

### Fix

- **ic-certification**: allow empty hash trees to be merged with other hash trees

### Refactor

- restructure examples and http certification tests

## 2.3.0 (2024-01-15)

### Feat

- **ic-http-certification**: add upgrade property to HttpResponse struct

### Fix

- **ic-certification-testing**: remove unnecessary CertificationTestError conversion

## 2.2.0 (2024-01-11)

### Feat

- update candid

## 2.1.0 (2024-01-11)

### Feat

- add bls signature cache
- **ic-http-certification**: add certification builder

## 2.0.1 (2023-12-20)

### Fix

- Revert "chore: bump candid to 0.10"

## 2.0.0 (2023-12-20)

### Feat

- move request and response hashing from ic-response-verification to ic-http-certification
- migrate http request and response types from ic-response-verification to ic-http-certification
- add copy on write support to CEL definition types
- add cel builder to ic-http-certification crate
- add-ic-http-certification-crate add CEL expression generation

### Fix

- disallow nested delegations when verifying certificates
- missing certification object in CEL expressions

## 1.3.0 (2023-11-17)

### Feat

- add nested rb_tree to ic_certification
- add rb_tree to ic_certification crate

### Fix

- update dependencies

## 1.2.0 (2023-09-15)

### Feat

- add ic-certification library

### Fix

- handle non-latin characters in URL path

### Refactor

- rename variable

## 1.1.0 (2023-08-25)

### Feat

- add certificate verification library

### Fix

- fix url decoding for encoded query strings

## 1.0.2 (2023-08-16)

### Fix

- allow for padded and unpadded base64 encoded headers

## 1.0.1 (2023-08-14)

### Fix

- add missing support for encoded urls

## 1.0.0 (2023-08-03)

### BREAKING CHANGE

- re #TT-80
- re #TT-79
- re #TT-205

### Feat

- always return a result/exception when response verification fails
- enable web logs and panic hook for response verification library
- add test utils wasm package
- add certificate verification JS library
- Added verification failed reason to the js binding
- return a more specific type for verification result

### Fix

- remove temporary comment
- add missing request body hashing

### Refactor

- update verify certification params interface name
- remove redundant npm pre scripts
- updated v2 e2e test cases to reuse load asset logic
- remove redundant package.sh code and setup-nodejs actions
- migrate to PNPM workspace
- Add more specific errors for verification version 2 failure
- Standardize verification errors as reasons

## 0.3.0 (2023-05-04)

### Feat

- **hash**: add support for byte values

### Refactor

- **hash**: move representation independent hash into its own crate
- high level mod structure

## 0.2.1 (2023-04-14)

### Fix

- do not throw an error when body is larger than 10mb, body size should be limited by consumers

## 0.2.0 (2023-04-14)

### Feat

- add verification version to certification result

## 0.1.1 (2023-04-04)

### Fix

- improve wildcard absence checking
- expr_path validation fixes

## 0.1.0 (2023-03-20)

### Feat

- update tree representation when request certification is skipped
- allow consumers to specify the minimum verification version
- add JS feature to hide web wasm features
- validate no certification cel expression
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

- update year and author in license file
- apply release profile to wasm crate properly
- do not panic if response body is too large
- response returned as certified even when verification fails
- do not allow exact match requests that are a subset of the request URL path
- handling of trailing slashes in request and expression paths
- add mising expr_path validation checks
- update agent-rs package
- spec incompatibilities
- fixed incorrect parameter type of validate_expr_hash function
- validate against encoded and decoded body sha
- hash encoded body for v2 response verification instead of decoded body
- fixes cargo lock duplicate entry for ic-certification
- representation independant hash should allow for duplicate keys

### Refactor

- return None for uncertified status_code instead of 0
- update GIT_BRANCH variable to more specific name
- migrate from bazel to wasm-pack
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

- improve wasm binary size
- add binaryen wasm opt support
