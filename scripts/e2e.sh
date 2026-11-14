#!/bin/bash

# Runs the end-to-end tests against the response_verification_tests_frontend
# canister deployed to a local icp-cli network.

CANISTER_NAME="response_verification_tests_frontend"

print_usage() {
  echo "Run the end to end tests"
  echo
  echo "Usage: $0 [options]"
  echo
  echo "Options:"
  echo "  -h                Show this help message and exit"
  echo
}

check_icp_command() {
  if ! command -v icp &> /dev/null; then
    echo "icp command was not found in your path"
    exit 3
  fi
}

network_start() {
  echo "Starting local network..."

  icp network start -d || exit 1

  REPLICA_ADDRESS=$(icp network status --json | sed -n 's/.*"api_url": *"\([^"]*\)".*/\1/p')
  REPLICA_ADDRESS="${REPLICA_ADDRESS%/}"

  echo "Local network running at $REPLICA_ADDRESS."
}

network_stop() {
  echo "Stopping local network..."

  icp network stop
}

deploy_test_canister() {
  echo "Deploying $CANISTER_NAME..."

  icp deploy "$CANISTER_NAME" || clean_exit

  CANISTER_ID=$(icp canister status "$CANISTER_NAME" --id-only) || clean_exit
  echo "$CANISTER_ID"
}

clean_exit() {
  echo "Performing clean exit..."

  network_stop

  echo "TESTS FAILED!"
  exit 1
}

run_e2e_tests() {
  echo "Running e2e tests..."

  if [ -z "$REPLICA_ADDRESS" ]; then
    echo "REPLICA_ADDRESS must be defined!"
    clean_exit
  fi

  if [ -z "$CANISTER_ID" ]; then
    echo "CANISTER_ID must be defined!"
    clean_exit
  fi

  REPLICA_ADDRESS=$REPLICA_ADDRESS RUST_BACKTRACE=1 cargo run -p ic-response-verification-tests -- "$CANISTER_ID" || clean_exit

  pnpm run -F @dfinity/response-verification build || clean_exit
  REPLICA_ADDRESS=$REPLICA_ADDRESS pnpm run -F response-verification-tests e2e-test -- "$CANISTER_ID" || clean_exit
}

for arg in "$@"; do
  case $arg in
    -h)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg"
      exit 1
      ;;
  esac
done

check_icp_command

pnpm i --frozen-lockfile

network_start
deploy_test_canister
run_e2e_tests
network_stop

echo "TESTS PASSED!"
