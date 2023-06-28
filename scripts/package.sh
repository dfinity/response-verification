PKG_ROOT=$1
OUT_DIR=$2

build_release_packages() {
    wasm-pack build --target web --out-name web --out-dir $OUT_DIR/web --release $PKG_ROOT
    wasm-pack build --target nodejs --out-name nodejs --out-dir $OUT_DIR/nodejs --release $PKG_ROOT
}

build_debug_packages() {
    wasm-pack build --target web --out-name web --out-dir $OUT_DIR/debug/dist/web --dev $PKG_ROOT -- --features "debug"
    wasm-pack build --target nodejs --out-name nodejs --out-dir $OUT_DIR/debug/dist/nodejs --dev $PKG_ROOT -- --features "debug"
}

delete_generated_files() {
    find $OUT_DIR -name ".gitignore" -type f -delete
    find $OUT_DIR -name "README.md" -type f -delete
    find $OUT_DIR -name "package.json" -type f -delete
    find $OUT_DIR -name "LICENSE" -type f -delete
}

add_debug_files() {
    cp $PKG_ROOT/package.json $OUT_DIR/debug/
    cp $PKG_ROOT/LICENSE $OUT_DIR/debug/
}

build_release_packages
build_debug_packages
delete_generated_files
add_debug_files
