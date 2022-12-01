use std::cmp::min;

// RFC4648 alphabet
const ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut ret = Vec::with_capacity((data.len() + 3) / 4 * 5);

    for chunk in data.chunks(5) {
        let buf = {
            let mut buf = [0u8; 5];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = b;
            }
            buf
        };
        ret.push(ALPHABET[((buf[0] & 0xF8) >> 3) as usize]);
        ret.push(ALPHABET[(((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)) as usize]);
        ret.push(ALPHABET[((buf[1] & 0x3E) >> 1) as usize]);
        ret.push(ALPHABET[(((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)) as usize]);
        ret.push(ALPHABET[(((buf[2] & 0x0F) << 1) | (buf[3] >> 7)) as usize]);
        ret.push(ALPHABET[((buf[3] & 0x7C) >> 2) as usize]);
        ret.push(ALPHABET[(((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)) as usize]);
        ret.push(ALPHABET[(buf[4] & 0x1F) as usize]);
    }

    if data.len() % 5 != 0 {
        let len = ret.len();
        let num_extra = 8 - (data.len() % 5 * 8 + 4) / 5;

        ret.truncate(len - num_extra);
    }

    String::from_utf8(ret).unwrap()
}

/// RFC4648 inverse alphabet
const INV_ALPHABET: [i8; 43] = [
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, 0, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];

pub fn base32_decode(data: &str) -> Option<Vec<u8>> {
    if !data.is_ascii() {
        return None;
    }
    let data = data.as_bytes();
    let mut unpadded_data_length = data.len();
    for i in 1..min(6, data.len()) + 1 {
        if data[data.len() - i] != b'=' {
            break;
        }
        unpadded_data_length -= 1;
    }
    let output_length = unpadded_data_length * 5 / 8;
    let mut ret = Vec::with_capacity((output_length + 4) / 5 * 5);
    for chunk in data.chunks(8) {
        let buf = {
            let mut buf = [0u8; 8];
            for (i, &c) in chunk.iter().enumerate() {
                match INV_ALPHABET.get(c.to_ascii_uppercase().wrapping_sub(b'0') as usize) {
                    Some(&-1) | None => return None,
                    Some(&value) => buf[i] = value as u8,
                };
            }
            buf
        };
        ret.push((buf[0] << 3) | (buf[1] >> 2));
        ret.push((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4));
        ret.push((buf[3] << 4) | (buf[4] >> 1));
        ret.push((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3));
        ret.push((buf[6] << 5) | buf[7]);
    }
    ret.truncate(output_length);
    Some(ret)
}

#[cfg(test)]
#[allow(dead_code, unused_attributes)]
mod test {
    use super::*;

    #[test]
    fn masks_unpadded_rfc4648() {
        assert_eq!(
            base32_encode(&[0xF8, 0x3E, 0x7F, 0x83, 0xE7]),
            "7A7H7A7H"
        );

        assert_eq!(
            base32_encode(&[0x77, 0xC1, 0xF7, 0x7C, 0x1F]),
            "O7A7O7A7"
        );

        assert_eq!(
            base32_encode(&[0xF8, 0x3E, 0x7F, 0x83]),
            "7A7H7AY"
        );

        assert_eq!(
            base32_decode("7A7H7A7H").unwrap(),
            [0xF8, 0x3E, 0x7F, 0x83, 0xE7]
        );

        assert_eq!(
            base32_decode("O7A7O7A7").unwrap(),
            [0x77, 0xC1, 0xF7, 0x7C, 0x1F]
        );

        assert_eq!(
            base32_decode(
                &base32_encode(&[0xF8, 0x3E, 0x7F, 0x83]),
            ).unwrap(),
            [0xF8, 0x3E, 0x7F, 0x83]
        );

        assert_eq!(base32_decode(","), None);
    }
}
