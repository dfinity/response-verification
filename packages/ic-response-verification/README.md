# Response Verification

Response verification on the [Internet Computer](https://dfinity.org) is the process of verifying that an HTTP-compatible canister response from a replica has gone through consensus with other replicas hosting the same canister. It is the counterpart to [HTTP Certification](#http-certification).

The `ic-response-verification` and `@dfinity/response-verification` packages encapsulate this verification protocol. It is used by [ICX Proxy](https://github.com/dfinity/ic/tree/master/rs/boundary_node/icx_proxy) and the [local HTTP Proxy](https://github.com/dfinity/http-proxy) and may be used by other implementations of the [HTTP Gateway Protocol](https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway) in the future.
