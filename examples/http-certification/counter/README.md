# Certifying an HTTP counter canister

## Overview

## Prerequisites

## Testing out the canister

Start DFX:

```shell
dfx start --clean --background
```

Deploy the canister:

```shell
dfx deploy http_certification_counter_backend
```

Make a GET request to fetch the current count from the canister using cURL:

```shell
curl -v http://localhost:$(dfx info webserver-port)?canisterId=$(dfx canister id http_certification_counter_backend)
```

Make a POST request to increment and fetch the new count from the canister using cURL:

```shell
curl -v -X POST http://localhost:$(dfx info webserver-port)?canisterId=$(dfx canister id http_certification_counter_backend)
```
