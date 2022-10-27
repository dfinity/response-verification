"""Binaryen toolchain configuration"""

load("//binaryen:binaryen_platforms.bzl", "BINARYEN_PLATFORMS")

def _binaryen_toolchain_impl(ctx):
    return [
        platform_common.ToolchainInfo(
            wasm_opt_path = ctx.executable.wasm_opt_path,
        ),
    ]

_binaryen_toolchain = rule(
    implementation = _binaryen_toolchain_impl,
    attrs = {
        "wasm_opt_path": attr.label(
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
    },
)

def configure_binaryen_toolchain(name, exec_compatible_with, bin_path):
    """Configures a binary toolchain given a name, platform constraints and a wasm-opt binary path

    Args:
        name: unique name for this toolchain, in the form "{name}_binaryen_{platform}"
        bin_path: path to the binaryen bin directory
        exec_compatible_with: list of platform constraints
    """

    _binaryen_toolchain(
        name = name,
        wasm_opt_path = "%s//:bin/wasm-opt" % bin_path,
    )

    native.toolchain(
        name = "%s_toolchain" % name,
        exec_compatible_with = exec_compatible_with,
        toolchain = name,
        toolchain_type = "//binaryen:toolchain_type",
    )

def configure_binaryen_toolchains(name = ""):
    """Configures binaryen toolchains for a list of supported platforms

    Args:
        name: unused
    """

    for name, meta in BINARYEN_PLATFORMS.items():
        name = "binaryen_%s" % name

        configure_binaryen_toolchain(
            name = name,
            exec_compatible_with = meta.exec_compatible_with,
            bin_path = "@%s_repo" % name,
        )
