"""Info for Binaryen binary executables"""

_VERSION = "110"

_LINUX_AMD64_SHA = "978d794d3cd608b2c10573f7b7b2341a011a9804f4aae7efb608ed8751970faa"
_DARWIN_AMD64_SHA = "8b24a1be1006811908a64219109df97af6f3423d619bb9d344e7f57d07f5f11c"
_DARWIN_ARM64_SHA = "dd38b9fe45dd93a4160e702ace3d8b885a35a05b9d8ea87c07bd84e019b4aeab"
_WINDOWS_AMD64_SHA = "a118decd2bf0359f4275aad2d41394b4b507c7a53d10f5253d29338d0057b48c"

_DOWNLOAD_URL = "https://github.com/WebAssembly/binaryen/releases/download/version_{version}/binaryen-version_{version}-{platform}.tar.gz"

PACKAGE_PREFIX = "binaryen-version_%s" % _VERSION

BINARYEN_PLATFORMS = dict({
    "linux_amd64": struct(
        sha = _LINUX_AMD64_SHA,
        urls = [_DOWNLOAD_URL.format(version = _VERSION, platform = "x86_64-linux")],
        exec_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:x86_64",
        ],
    ),
    "darwin_amd64": struct(
        sha = _DARWIN_AMD64_SHA,
        urls = [_DOWNLOAD_URL.format(version = _VERSION, platform = "x86_64-macos")],
        exec_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:x86_64",
        ],
    ),
    "darwin_arm64": struct(
        sha = _DARWIN_ARM64_SHA,
        urls = [_DOWNLOAD_URL.format(version = _VERSION, platform = "arm64-macos")],
        exec_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:arm64",
        ],
    ),
    "windows_amd64": struct(
        sha = _WINDOWS_AMD64_SHA,
        urls = [_DOWNLOAD_URL.format(version = _VERSION, platform = "x86_64-windows")],
        exec_compatible_with = [
            "@platforms//os:windows",
            "@platforms//cpu:x86_64",
        ],
    ),
})
