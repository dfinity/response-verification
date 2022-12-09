"""Binaryen repositories configuration"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", _http_archive = "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//bazel/binaryen/private:platforms.bzl", "PLATFORMS")
load("//bazel/binaryen/private:versions.bzl", "VERSIONS")

URL_TEMPLATE = "https://github.com/WebAssembly/binaryen/releases/download/version_{version}/binaryen-version_{version}-{platform}.tar.gz"
PREFIX_TEMPLATE = "binaryen-version_{version}"

def http_archive(name, **kwargs):
    maybe(_http_archive, name = name, **kwargs)

def binaryen_register_toolchains(name = "", version = "111"):
    """Configures a repository with platform dependant toolchains

    Args:
        name: unused
        version: the desired version of binaryen
    """

    for name in PLATFORMS.keys():
        url = URL_TEMPLATE.format(version = version, platform = name)
        package_prefix = PREFIX_TEMPLATE.format(version = version)

        http_archive(
            name = "binaryen_%s_repo" % name,
            urls = [url],
            strip_prefix = package_prefix,
            build_file_content = """exports_files(["bin/wasm-opt"])""",
            integrity = VERSIONS[version][name],
        )

        native.register_toolchains("//bazel/binaryen:binaryen_%s_toolchain" % name)
