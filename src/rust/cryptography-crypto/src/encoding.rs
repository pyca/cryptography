// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub fn hex_decode(v: &str) -> Option<Vec<u8>> {
    if v.len() % 2 != 0 {
        return None;
    }

    let mut b = Vec::with_capacity(v.len() / 2);
    let v = v.as_bytes();
    for i in (0..v.len()).step_by(2) {
        let high = match v[i] {
            b @ b'0'..=b'9' => b - b'0',
            b @ b'a'..=b'f' => b - b'a' + 10,
            b @ b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };

        let low = match v[i + 1] {
            b @ b'0'..=b'9' => b - b'0',
            b @ b'a'..=b'f' => b - b'a' + 10,
            b @ b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };

        b.push((high << 4) | low);
    }

    Some(b)
}

#[cfg(test)]
mod tests {
    use super::hex_decode;

    #[test]
    fn test_hex_decode() {
        for (text, expected) in [
            ("", Some(vec![])),
            ("00", Some(vec![0])),
            ("0", None),
            ("12-0", None),
            ("120-", None),
            ("ab", Some(vec![0xAB])),
            ("AB", Some(vec![0xAB])),
            ("ABCD", Some(vec![0xAB, 0xCD])),
        ] {
            assert_eq!(hex_decode(text), expected);
        }
    }
}
