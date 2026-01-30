#!/bin/bash


# Set the dfx command, this might be overwritten
DFX=dfx

# By default, we use the local DFX
USE_LATEST_DFX=0

# in case we decide to use the latest dfx
SDK_GIT_BRANCH="master"
SDK_REPO_DIR="$(pwd)/tmp/sdk"

# Function to display usage
print_usage() {
  echo "Run the end to end tests"
  echo
  echo "Usage: $0 [options]"
  echo
  echo "Options:"
  echo "  -h                Show this help message and exit"
  echo "  --use-latest-dfx  Clone, build and use the latest dfx"
  echo
}


# Download the SDK repo so we can build and test against the latest changes
download_sdk_repo() {

  if [ -d "$SDK_REPO_DIR" ]; then
    echo "SDK repo already cloned, updating..."

    pushd "$SDK_REPO_DIR" || clean_exit
    git reset --hard
    git clean -fxd -e target
    git fetch
    git checkout "$SDK_GIT_BRANCH"
    git pull
    popd || clean_exit
  else
    echo "SDK repo not cloned yet, cloning..."

    git clone "https://github.com/dfinity/sdk" "$SDK_REPO_DIR"
    pushd "$SDK_REPO_DIR" || clean_exit
    git checkout "$SDK_GIT_BRANCH"
    popd || clean_exit
  fi
}

# check if the $DFX command exists
check_dfx_command() {
  if ! command -v $DFX &> /dev/null
  then
      echo "$DFX command was not found in your path"
      exit 3
  fi
}

build_dfx() {
  echo "Building DFX..."

  pushd "$SDK_REPO_DIR" || clean_exit
  cargo build -p dfx

  # override dfx path
  DFX="$(pwd)/target/debug/dfx"
  popd || clean_exit

  echo "DFX built at $DFX."
}

dfx_start() {
  echo "Starting DFX..."

  check_dfx_command

  "$DFX" start --clean --background -qq --log file --logfile "./replica.log" -vv

  DFX_REPLICA_PORT=$("$DFX" info webserver-port)
  DFX_REPLICA_ADDRESS="http://localhost:$DFX_REPLICA_PORT"

  echo "DFX local replica running at $DFX_REPLICA_ADDRESS."
}

dfx_stop() {
  echo "Stopping DFX..."

  check_dfx_command

  "$DFX" stop
}

deploy_dfx_project() {
  echo "Deploying DFX project..."

  check_dfx_command

  "$DFX" deploy response_verification_tests_frontend

  echo "getting canister id..."
  "$DFX" canister id response_verification_tests_frontend
  DFX_CANISTER_ID=$("$DFX" canister id response_verification_tests_frontend)
  echo "$DFX_CANISTER_ID"
}

clean_exit() {
  echo "Performing clean exit..."

  dfx_stop

  echo "TESTS FAILED!"
  exit 1
}

run_e2e_tests() {
  echo "Running e2e tests..."

  if [ -z "$DFX_REPLICA_ADDRESS" ]; then
    echo "$DFX_REPLICA_ADDRESS must be defined!"
    clean_exit
  fi

  if [ -z "$DFX_CANISTER_ID" ]; then
    echo "DFX_CANISTER_ID must be defined!"
    clean_exit
  fi

  echo "Run Rust e2e tests..."
  DFX_REPLICA_ADDRESS=$DFX_REPLICA_ADDRESS RUST_BACKTRACE=1 cargo run -p ic-response-verification-tests -- "$DFX_CANISTER_ID" || clean_exit

  echo "Run JS e2e tests..."
  pnpm run -F @dfinity/response-verification build || clean_exit
  DFX_REPLICA_ADDRESS=$DFX_REPLICA_ADDRESS pnpm run -F response-verification-tests e2e-test -- "$DFX_CANISTER_ID" || clean_exit
}

# Parse the script arguments
for arg in "$@"; do
  case $arg in
    --use-latest-dfx)
      USE_LATEST_DFX=1
      shift
      ;;
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


pnpm i --frozen-lockfile

if [ $USE_LATEST_DFX -eq 1 ]; then
  # build latest dfx
  download_sdk_repo
  build_dfx
fi

dfx_start
deploy_dfx_project
run_e2e_tests
dfx_stop

echo "TESTS PASSED!"
