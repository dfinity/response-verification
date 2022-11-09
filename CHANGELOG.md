## Unreleased

### Feat

- **response-verification**: add initial request, response interface
- **certificate-header**: add certificate header handling (#5)

### Refactor

- use nom to parse header field instead of regex
- rename pub interface function for JS to verify_request_response_pair
- remove `serde` in favor of `js-sys`

## 0.0.0 (2022-09-29)
