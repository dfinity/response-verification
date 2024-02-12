# Response Verification

Response verification on the [Internet Computer](https://dfinity.org) is the process of verifying that an HTTP-compatible canister response from a replica has gone through consensus with other replicas hosting the same canister. It is the counterpart to [HTTP Certification](#http-certification).

The `ic-response-verification` and `@dfinity/response-verification` packages encapsulate this verification protocol. It is used by [ICX Proxy](https://github.com/dfinity/ic/tree/master/rs/boundary_node/icx_proxy) and the [local HTTP Proxy](https://github.com/dfinity/http-proxy) and may be used by other implementations of the [HTTP Gateway Protocol](https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway) in the future.

## Usage

```javascript
import initResponseVerification, {
  verifyRequestResponsePair,
  ResponseVerificationError,
  ResponseVerificationErrorCode,
} from '@dfinity/response-verification';

// this is necessary for web, but not for NodeJS consumers
await initResponseVerification();

try {
  const result = verifyRequestResponsePair(
    request,
    response,
    canister_id,
    current_time_ns,
    max_cert_time_offset_ns,
    fromHex(IC_ROOT_KEY),
  );

  // do something with the result
  // `result.passed` will be true if verification succeeds, false otherwise, and
  // `result.response` will contain the certified response object if verification was successful.
} catch (error) {
  if (error instanceof ResponseVerificationError) {
    switch (error.code) {
      case ResponseVerificationErrorCode.MalformedCbor:
        // the cbor returned from the replica was malformed.
        // ...
        break;

      case ResponseVerificationErrorCode.MalformedCertificate:
        // the certificate returned from the replica was malformed.
        // ...
        break;

      // Other error cases...
    }
  }
}
```

## Examples

See the following for working examples:

- [Web](https://github.com/dfinity/response-verification/tree/main/examples/response-verification/web)
- [NodeJS](https://github.com/dfinity/response-verification/tree/main/examples/response-verification/nodejs)

Note that when bundling for a service worker with Webpack. The `target` property must be set to `webworker`.
