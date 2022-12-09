"""Info for supported binaryen versions"""

# The integrity hashes can be computed with
# shasum -b -a 384 [downloaded file] | awk '{ print $1 }' | xxd -r -p | base64
VERSIONS = {
    "111": {
        "arm64-macos": "sha384-yStc8t9AqRhphxARRJtk5+dIK86b1/72cg63eYn7vzq+vc4jnkupHOf2+Uv/QSt9",
        "x86_64-linux": "sha384-EBoaPTre90CFuanDD0dPkfuSLEKe90cSoyNju8ImH9YrHcGMDRju+HlQkAwo8ofc",
        "x86_64-macos": "sha384-E+6ED8w8VHeZTNLijFV+67wdz0eP5a6tfQN+WvAfXdSgE2HPvxM55TZToCSZXLxp",
        "x86_64-windows": "sha384-X+/BamZalglv6yB/45e30qlzVlLIqXgxo062yV1FWxAewsYbTxnIzkWf9l4N4Nci",
    },
    "110": {
        "arm64-macos": "sha384-JTqd8BsnPnlN7UjqL0ZWiuU4yK8ATgqGq2zoxQJQUps75gAQaLHaWUuyXPkgW5Ei",
        "x86_64-linux": "sha384-vFwWpdMQo8AGA7fQuIY0SU9xJuDU1VkwySkoUuu7lmcs+tOuMGvmeQI+XcJC/tL8",
        "x86_64-macos": "sha384-3yTrcRgbsuL/MMjiLemUEAlUuFiuNE9Oqjmn52YJjQQ1/0bEsAEcM1blcJtpLLgu",
        "x86_64-windows": "sha384-EBV1t6Qo2hv8a30OF1HKIjbP/NAo6ZY6Az7J6M/CgWgsQiKWZrJFX+Fk1mTGpM4v",
    },
}
