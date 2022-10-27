"""Binaryen repositories configuration"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//binaryen:binaryen_platforms.bzl", "BINARYEN_PLATFORMS", "PACKAGE_PREFIX")

def binaryen_repositories(name = ""):
    """Configures a repository with platform dependant toolchains

    Args:
        name: unused
    """

    for name, meta in BINARYEN_PLATFORMS.items():
        maybe(
            http_archive,
            name = "binaryen_%s_repo" % name,
            urls = meta.urls,
            strip_prefix = PACKAGE_PREFIX,
            # build_file_content = """exports_files(["bin/wasm-opt"])""",
            build_file_content = """exports_files(["bin/wasm-opt"])""",
            sha256 = meta.sha,
        )

        native.register_toolchains("//binaryen:binaryen_%s_toolchain" % name)
