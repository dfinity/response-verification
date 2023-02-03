build_release_packages() {
    wasm-pack build --target web --out-name web --out-dir ../../pkg/web --release packages/ic-response-verification-wasm
    wasm-pack build --target nodejs --out-name nodejs --out-dir ../../pkg/nodejs --release packages/ic-response-verification-wasm
}

build_debug_packages() {
    wasm-pack build --target web --out-name web --out-dir ../../pkg/debug/web --profiling packages/ic-response-verification-wasm -- --features "debug"
    wasm-pack build --target nodejs --out-name nodejs --out-dir ../../pkg/debug/nodejs --profiling packages/ic-response-verification-wasm -- --features "debug"
}

delete_generated_files() {
    find ./pkg -name ".gitignore" -type f -delete
    find ./pkg -name "README.md" -type f -delete
    find ./pkg -name "package.json" -type f -delete
    find ./pkg -name "package-lock.json" -type f -delete
}

add_release_files() {
    cp ./packages/ic-response-verification-wasm/package.json ./pkg/
    cp ./packages/ic-response-verification-wasm/package-lock.json ./pkg/
    cp ./packages/ic-response-verification-wasm/README.md ./pkg/
    cp ./packages/ic-response-verification-wasm/LICENSE ./pkg/
}

add_debug_files() {
    cp ./packages/ic-response-verification-wasm/package.json ./pkg/debug/
    cp ./packages/ic-response-verification-wasm/package-lock.json ./pkg/debug/
    cp ./packages/ic-response-verification-wasm/LICENSE ./pkg/debug/
}

build_release_packages
build_debug_packages
delete_generated_files
add_release_files
add_debug_files
