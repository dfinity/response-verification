"""Public entry point to all Binaryen rules and supported APIs."""

load(
    "//bazel/binaryen/private:wasm_opt.bzl",
    _wasm_opt = "wasm_opt",
)

wasm_opt = _wasm_opt
