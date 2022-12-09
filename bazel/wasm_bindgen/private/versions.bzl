"""Info for supported wasm bindgen versions"""

# The integrity hashes can be computed with
# shasum -b -a 384 [downloaded file] | awk '{ print $1 }' | xxd -r -p | base64
VERSIONS = {
    "0.2.83": {
        "x86_64-apple-darwin":"sha384-xNqwMQofP2m/Hk0uW+bbSK6MTDw4hd1FkxNLSC+5qi4rIGyc3Rg9+o2GZhvcJ7X1",
        "x86_64-pc-windows-msvc":"sha384-X9dYGfQVqdmOy0+tiUbHSQA+FdBMfg15Pboobss5Ubr6nO0lx/Xf1/Q+O0k46TNL",
        "x86_64-unknown-linux-musl":"sha384-6tStbrVaEtkSMnwOc4h6j7W9VmcJQbNsBHQiscUloA67CwGoIWoqjtN5+e4hmB8W",
    },
}
