# Response Verification

Response verification on the [Internet Computer](https://dfinity.org) is the process of verifying that an HTTP-compatible canister response from a replica has gone through consensus with other replicas hosting the same canister. It is the counterpart to [HTTP Certification](#http-certification).

The `ic-response-verification` and `@dfinity/response-verification` packages encapsulate this verification protocol. It is primarily used by [the `ic-http-gateway` library](https://github.com/dfinity/http-gateway/tree/main/packages/ic-http-gateway) and may be used by other implementations of the [HTTP Gateway Protocol](https://internetcomputer.org/docs/references/ic-interface-spec/#http-gateway) in the future.