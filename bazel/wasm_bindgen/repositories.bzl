"""Wasm Bindgen repositories configuration"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", _http_archive = "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//bazel/wasm_bindgen/private:platforms.bzl", "PLATFORMS")
load("//bazel/wasm_bindgen/private:versions.bzl", "VERSIONS")

URL_TEMPLATE = "https://github.com/rustwasm/wasm-bindgen/releases/download/{version}/wasm-bindgen-{version}-{platform}.tar.gz"
PREFIX_TEMPLATE = "wasm-bindgen-{version}-{platform}"

def http_archive(name, **kwargs):
    maybe(_http_archive, name = name, **kwargs)

def wasm_bindgen_register_toolchains(name = "", version = "0.2.83"):
    """Configures a repository with platform dependant toolchains

    Args:
        name: unused
        version: the desired version of wasm-bindgen
    """

    for name in PLATFORMS.keys():
        url = URL_TEMPLATE.format(version = version, platform = name)
        package_prefix = PREFIX_TEMPLATE.format(version = version, platform = name)

        http_archive(
            name = "wasm_bindgen_%s_repo" % name,
            urls = [url],
            strip_prefix = package_prefix,
            build_file_content = """exports_files(["wasm-bindgen", "wasm-bindgen-test-runner"])""",
            integrity = VERSIONS[version][name],
        )

        native.register_toolchains("//bazel/wasm_bindgen:wasm_bindgen_%s_toolchain" % name)
