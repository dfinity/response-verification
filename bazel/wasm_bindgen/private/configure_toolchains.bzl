"""Wasm Bindgen toolchain configuration"""

load("@rules_rust//bindgen:bindgen.bzl", "rust_bindgen_toolchain")
load("//bazel/wasm_bindgen/private:platforms.bzl", "PLATFORMS")
load("@bazel_skylib//rules:native_binary.bzl", "native_binary")

def configure_toolchain(name, compatible_with, bin_path):
    """Configures a wasm bindgen toolchain given a name, platform constraints and a wasm-opt binary path

    Args:
        name: unique name for this toolchain, in the form "{name}_wasm_bindgen_{platform}"
        bin_path: path to the wasm bindgen bin directory
        compatible_with: list of platform constraints
    """

    native_binary(
        name = "%s_binary" % name,
        src = "%s//:wasm-bindgen" % bin_path,
        out = "%s_binary" % name,
    )

    rust_bindgen_toolchain(
        name = name,
        bindgen = "%s_binary" % name,
    )

    native.toolchain(
        name = "%s_toolchain" % name,
        exec_compatible_with = compatible_with,
        toolchain = name,
        toolchain_type = "@rules_rust//wasm_bindgen:toolchain_type",
    )

def configure_toolchains(name = ""):
    """Configures wasm bindgen toolchains for a list of supported platforms

    Args:
        name: unused
    """

    for name, meta in PLATFORMS.items():
        name = "wasm_bindgen_%s" % name

        configure_toolchain(
            name = name,
            compatible_with = meta.compatible_with,
            bin_path = "@%s_repo" % name,
        )
