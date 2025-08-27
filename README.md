# Response Verification

## Introduction

The Internet Computer Protocol features two primary types of calls that can be used to interact with canisters: query calls and update calls.

| Query Calls                                            | Update Calls                                        |
| ------------------------------------------------------ | --------------------------------------------------- |
| Readonly, cannot change canister state.                | Can change canister state.                          |
| Response does not go through consensus.                | Response goes through consensus.                    |
| Answered by a single replica on the canister's subnet. | Answered by every replica on the canister's subnet. |

The different properties of query and update calls present a trade off in terms of performance and security. Since query call responses do not go through consensus and are fulfilled by only a single replica, they are much faster than update calls. In contrast, the lack of consensus poses a security concern and these responses cannot be trusted since any individual replica can arbitrarily change the response.

Canister certification provides a solution to this problem by pre-calculating responses and putting those pre-calculated responses through consensus. Consensus will produce a certificate for the pre-calculated responses that can be returned with the responses by any individual replica. Any clients requesting these responses can then verify this certificate to validate that consensus has agreed on this response prior to the request. This approach will give the performance characteristics of a query call, with the security profile of an update call, providing the best of both types of calls.

Canister certification is enabled by the [Certified data](https://internetcomputer.org/docs/references/ic-interface-spec/#system-api-certified-data) feature of the Internet Computer. This feature allows canisters to specify a 32 byte blob that will be included in consensus. How this 32 byte blob is determined is entirely up to canister developers to decide for themselves. This repo provides solutions that rely on merkle trees and won't discuss any other methods, but there are many other possibilities for imaginative developers that would like to roll their own solution.

In the next consensus round following this 32 byte blob being set (via [`ic0.certified_data_set`](https://internetcomputer.org/docs/references/ic-interface-spec/#system-api-certified-data)), the Internet Computer will prepare a certificate for the canister. This certificate, and the process for verifying it, is described in detail in the [interface spec](https://internetcomputer.org/docs/references/ic-interface-spec/#certification).

When responding to query calls, a canister can request the certificate (via [`ic0.certified_data_size`](https://internetcomputer.org/docs/references/ic-interface-spec/#system-api-certified-data) and [`ic0.certified_data_copy`](https://internetcomputer.org/docs/references/ic-interface-spec/#system-api-certified-data)) and then include this certificate in the response, to allow for clients to validate the response's authenticity.

## Standard Certification

The standard, or default, method of certification is the simplest form of certification. The high-level procedure for certification is as follows:

1. Pre-calculate any query call responses that need to be certified.
2. Arrange query call response hashes into a merkle tree.
3. Calculate the root hash of the merkle tree.
4. Set the root hash as the canister's certified data.
5. If an update call is received that changes state, return to step 1.
6. If a query call is received, return the pre-calculated response along with the certified data certificate.

There are a number of questions that a developer needs to answer on a per-project basis when using this style of certification that should be agreed upon with clients beforehand and done consistently by both client and canister:

- How are responses hashed?
  - What properties are included/excluded? (e.g., `response_timestamp` is excluded but `id` is included).
  - What format of each property is hashed? (e.g., leb, big/little endian encoding for numbers).
  - In what order are properties hashed? (e.g., sort properties alphabetically).
  - The [representation independent hash](https://internetcomputer.org/docs/references/ic-interface-spec/#hash-of-map) from the Internet Computer Protocol spec can be used, or serve as inspiration for developers.
- How are response hashes arranged in the tree?
  - Each exposed canister method should have a pre-determined path where its response hash will be presented in the merkle tree (e.g., the `get_count` method returns a response and the hash of this response is present at the `["count"]` path of the merkle tree).
  - This pre-determined path may use parameters of the request or calling principal to arrange more dynamic data in the tree (e.g., the `get_account` method returns a response and the hash of this response is present at the `["account", caller.to_text()]` path of the merkle tree).

### Process Flow

```mermaid
flowchart TB;
  subgraph lifecycle_hooks[Lifecycle hooks]
    init;
    post_upgrade;
  end
  init-->certification;
  post_upgrade-->certification;

  subgraph update_calls
    update_call;
    update_state;
    update_call-->update_state;
  end
  update_state-->certification;

  subgraph query_calls
    direction TB;

    query_call;
    serve_response[Serve pre-calculated response];
    query_call-->serve_response;
  end

  subgraph certification[Certification]
    direction TB;

    certification_step_one[pre-calculate response];
    certification_step_two[insert response hash into merkle tree];
    certification_step_three[calculate root hash of merkle tree];
    certification_step_four[set canister certified data];

    certification_step_one-->certification_step_two-->certification_step_three-->certification_step_four;
  end
```

### Resources

- [`ic-certification` Cargo crate](https://crates.io/crates/ic-certification).
- [`ic-certification` docs](https://docs.rs/ic-certification/latest/ic_certification).
- [Example with a certified counter](./examples/certification/certified-counter/README.md).
- [`ic-certification` source code](./packages/ic-certification/README.md).
- [`ic-representation-independant-hash` Cargo crate](https://crates.io/crates/ic-representation-independent-hash).
- [`ic-representation-independant-hash` docs](https://docs.rs/ic-representation-independent-hash/2.3.0/ic_representation_independent_hash).
- [`ic-representation-independent-hash` source code](./packages/ic-representation-independent-hash/README.md).

## Certificate verification

Certifications of a response need to be verified by the caller. The process for this is as follows:

1. Extract the canister's certificate from the response and verify it:
   - If the certificate has a delegation:
     1. Verify the delegation's signature using the Internet Comptuer Protocol's public key.
     2. Assert that the delegation is valid for the canister's canister ID.
     3. Extract the subnet's public key from the delegation.
     4. Verify the certificate's signature using the subnet's public key.
   - Otherwise:
     1. Verify the certificate's signature using the Internet Computer Protocol's public key.
2. Verify that the certificate's time is not too far in the past or future.
3. Extract the canister's merkle tree from the response and calculate it's root hash.
4. Ensure that the merkle tree's root hash matches the canister's certified data in the certificate.
5. Calculate the hash of the canister's response.
6. Ensure that the response hash is in the merkle tree at the expected path.

Steps 1 through 4 (inclusive) is encapsulated by the `@dfinity/certificate-verification` (JavaScript) and the `ic-certificate-verification` (Rust) packages.

For testing code that verifies responses, the `@dfinity/certification-testing` (JavaScript) and `ic-certification-testing` (Rust, unpublished) packages can be used to create certifications.

### Resources

- [`@dfinity/certificate-verification` source code](./packages/certificate-verification-js/README.md).
- [`@dfinity/certificate-verification` NPM package](https://www.npmjs.com/package/@dfinity/certificate-verification).
- [`ic-certificate-verification` Cargo crate](https://crates.io/crates/ic-certificate-verification).
- [`ic-certificate-verification` docs](https://docs.rs/ic-certificate-verification/2.3.0/ic_certificate_verification).
- [`ic-certificate-verification` source code](./packages/ic-certificate-verification/README.md).
- [`@dfinity/certification-testing` NPM package](https://www.npmjs.com/package/@dfinity/certification-testing).
- [`@dfinity/certification-testing` source code](./packages/ic-certification-testing-wasm/README.md).
- [`ic-certification-testing` source code (unpublished)](./packages/ic-certification-testing/README.md).

## HTTP Certification

Canisters may leverage the [HTTP Gateway Protocol](https://github.com/dfinity/http-gateway) to serve HTTP-compatible responses to HTTP-aware clients, such as a web browser. This is a much more involved process than [standard certification](#standard-certification). With [standard certification](#standard-certification) canister developers are free to make a lot of decisions on their own because they will likely also control the clients that will be performing certification. This is in contrast to HTTP certification where a generic client (the [HTTP Gateway](https://github.com/dfinity/http-gateway)) will verify all canisters implementing this protocol.

### Process Flow

```mermaid
flowchart TB;
  subgraph lifecycle_hooks[Lifecycle hooks]
    init;
    post_upgrade;
  end
  init-->certification;
  post_upgrade-->certification;

  subgraph query_calls[Query calls]
    http_request;
    should_upgrade{State change?};
    serve_response[Serve pre-calculated response];
    upgrade[Upgrade to update call];

    http_request-->should_upgrade;
    should_upgrade -- No-->serve_response;
    should_upgrade -- Yes-->upgrade;
  end
  upgrade-->update_calls;

  subgraph update_calls[Update calls]
    http_request_update;
    update_state;

    http_request_update-->update_state;
  end
  update_state-->certification;

  subgraph certification[Certification]
    direction TB;

    certification_step_one[pre-calculate response];
    certification_step_two[pre-calculate CEL expression];
    certification_step_three[pre-calculate certification];

    certification_step_one[pre-calculate response];
    certification_step_two[pre-calculate CEL expression];
    certification_step_three[insert response hash into merkle tree];
    certification_step_four[calculate root hash of merkle tree];
    certification_step_five[set canister certified data];

    certification_step_one-->certification_step_two-->certification_step_three-->certification_step_four-->certification_step_five;
  end
```

### Resources

- [`ic-http-certification` Cargo crate](https://crates.io/crates/ic-http-certification).
- [`ic-http-certification` docs](https://docs.rs/ic-http-certification/latest/ic_http_certification).
- [Example project serving a REST API](./examples/http-certification/json-api/README.md).
- [Example project with a custom implementation serving static assets](./examples/http-certification/custom-assets/README.md).
- [`ic-http-certification` source code](./packages/ic-http-certification/README.md).

## Asset Certification

Asset certification is a high level abstraction on [HTTP Certification](#http-certification) that allows canisters to serve static assets (e.g., HTML, CSS, JS, images, etc.) to clients. This is a common use case for web developers that want to host a website on the Internet Computer.

The `ic-asset-certification` crate provides a simple API for canisters to serve static assets. It is built on top of the `ic-http-certification` crate and provides a way to serve certified assets without needing to understand how HTTP certification works.

### Resources

- [`ic-asset-certification` Cargo crate](https://crates.io/crates/ic-asset-certification).
- [`ic-asset-certification` docs](https://docs.rs/ic-asset-certification/latest/ic_asset_certification).
- [Example project serving a static website](./examples/http-certification/assets/README.md).
- [`ic-asset-certification` source code](./packages/ic-asset-certification/README.md).

## Response Verification

Response verification on the [Internet Computer](https://dfinity.org) is the process of verifying that an HTTP-compatible canister response from a replica has gone through consensus with other replicas hosting the same canister. It is the client-side counterpart to [HTTP Certification](#http-certification) and [Asset Certification](#asset-certification).

The `ic-response-verification` and `@dfinity/response-verification` packages encapsulate this verification protocol. It is used by [ICX Proxy](https://github.com/dfinity/ic/tree/master/rs/boundary_node/icx_proxy) and the [local HTTP Proxy](https://github.com/dfinity/http-proxy) and may be used by other implementations of the [HTTP Gateway Protocol](https://internetcomputer.org/docs/references/ic-interface-spec/#http-gateway) in the future.

### Resources

- [`ic-response-verificaiton` source code](./packages/ic-response-verification/README.md)
- [`@dfinity/response-verification` source code](./packages/ic-response-verification-wasm/README.md)
- [Usage example in the `ic-http-gateway` library](https://github.com/dfinity/http-gateway/tree/main/packages/ic-http-gateway)

## Miscellaneous Projects

### Representation Independent Hash

This is a utility crate to implement [representation independent hashing](https://internetcomputer.org/docs/references/ic-interface-spec/#hash-of-map) of data.

- [`ic-representation-independant-hash` Cargo crate](https://crates.io/crates/ic-representation-independent-hash).
- [`ic-representation-independant-hash` docs](https://docs.rs/ic-representation-independent-hash/2.3.0/ic_representation_independent_hash).
- [`ic-representation-independent-hash` source code](./packages/ic-representation-independent-hash/README.md).

### CBOR

This is a utilty crate to implement decoding of CBOR-encoded data.

- [`ic-cbor` Cargo crate](https://crates.io/crates/ic-cbor).
- [`ic-cbor` docs](https://docs.rs/ic-cbor/2.3.0/ic_cbor).
- [`ic-cbor` source code](./packages/ic-cbor/README.md).

## Contributing

Contributions are welcome! Please refer to
[CONTRIBUTING.md](.github/CONTRIBUTING.md), where you can find all you need to
know to contribute to this project.

## License

This project is licensed under the [Apache-2.0 License](LICENSE).
