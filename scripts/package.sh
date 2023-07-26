PKG_ROOT=$1
OUT_DIR=$2

early_exit() {
  echo "Performing early exit..."

  exit 1
}

build_release_packages() {
  wasm-pack build --target web --out-name web --out-dir $OUT_DIR/web --release $PKG_ROOT || early_exit
  wasm-pack build --target nodejs --out-name nodejs --out-dir $OUT_DIR/nodejs --release $PKG_ROOT || early_exit
}

build_debug_packages() {
  wasm-pack build --target web --out-name web --out-dir $OUT_DIR/debug/dist/web --dev $PKG_ROOT -- --features "debug" || early_exit
  wasm-pack build --target nodejs --out-name nodejs --out-dir $OUT_DIR/debug/dist/nodejs --dev $PKG_ROOT -- --features "debug" || early_exit
}

delete_generated_files() {
  find $OUT_DIR -name ".gitignore" -type f -delete || early_exit
  find $OUT_DIR -name "README.md" -type f -delete || early_exit
  find $OUT_DIR -name "package.json" -type f -delete || early_exit
  find $OUT_DIR -name "LICENSE" -type f -delete || early_exit
}

add_debug_files() {
  cp $PKG_ROOT/package.json $OUT_DIR/debug/ || early_exit
  cp $PKG_ROOT/LICENSE $OUT_DIR/debug/ || early_exit
}

build_release_packages
build_debug_packages
delete_generated_files
add_debug_files
