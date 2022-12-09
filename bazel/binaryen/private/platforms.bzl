"""Info for supported binaryen platforms"""

PLATFORMS = {
    "x86_64-linux": struct(
        compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:x86_64",
        ],
    ),
    "x86_64-macos": struct(
        compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:x86_64",
        ],
    ),
    "arm64-macos": struct(
        compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:arm64",
        ],
    ),
    "x86_64-windows": struct(
        compatible_with = [
            "@platforms//os:windows",
            "@platforms//cpu:x86_64",
        ],
    ),
}
