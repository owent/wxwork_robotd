use std::fmt::{self, Display};
use std::iter::FromIterator;

#[derive(Clone, Copy)]
pub struct Engine<'a, 'b> {
    encode_map: &'a [char; 64],
    decode_map: &'b [u8; 128],
    padding_char: char,
}

impl<'a, 'b> fmt::Debug for Engine<'a, 'b> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "base64::Engine\n\tencode_map: {}\n\tdecode_map: {}\n\tpadding_char: {}",
            String::from_iter(self.encode_map.iter()),
            hex::encode(self.decode_map.as_ref()),
            if self.padding_char == '\0' {
                '-'
            } else {
                self.padding_char
            }
        )
    }
}

/// Errors that can occur while decoding.
#[derive(Clone, Debug)]
pub struct DecodeError {
    pub message: String,
    pub position: usize,
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Errors that can occur while encoding.
#[derive(Clone, Debug)]
pub struct EncodeError {
    pub message: String,
    pub position: usize,
}

impl Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl<'a, 'b> Engine<'a, 'b> {
    #[allow(non_snake_case, dead_code)]
    pub fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Result<String, EncodeError> {
        let input_bytes = input.as_ref();
        let input_len: usize = input_bytes.len();
        if input_len == 0 {
            return Ok(String::default());
        }

        let mut n = input_len.div_ceil(3);
        if n > ((usize::MAX - 1) / 4) {
            return Err(EncodeError {
                message: String::from("buffer too large"),
                position: 0,
            });
        }

        n *= 4;

        // no padding
        if self.padding_char == '\0' {
            let nopadding = input_len % 3;
            if 0 != nopadding {
                n -= 3 - nopadding;
            }
        }

        let mut ret = String::with_capacity(n);
        for i in 0..(input_len / 3) {
            let start_pos = i * 3;
            let C1 = input_bytes[start_pos];
            let C2 = input_bytes[start_pos + 1];
            let C3 = input_bytes[start_pos + 2];

            ret.push(self.encode_map[((C1 >> 2) & 0x3F) as usize]);
            ret.push(self.encode_map[((((C1 & 3) << 4) + (C2 >> 4)) & 0x3F) as usize]);
            ret.push(self.encode_map[((((C2 & 15) << 2) + (C3 >> 6)) & 0x3F) as usize]);
            ret.push(self.encode_map[(C3 & 0x3F) as usize]);
        }

        let tail_pos = (input_len / 3) * 3;
        if tail_pos < input_len {
            let C1 = input_bytes[tail_pos];
            let C2 = if tail_pos + 1 < input_len {
                input_bytes[tail_pos + 1]
            } else {
                0
            };

            ret.push(self.encode_map[((C1 >> 2) & 0x3F) as usize]);
            ret.push(self.encode_map[((((C1 & 3) << 4) + (C2 >> 4)) & 0x3F) as usize]);

            if (tail_pos + 1) < input_len {
                ret.push(self.encode_map[(((C2 & 15) << 2) & 0x3F) as usize]);
            } else if self.padding_char != '\0' {
                ret.push(self.padding_char);
            }

            if self.padding_char != '\0' {
                ret.push(self.padding_char);
            }
        }

        Ok(ret)
    }

    #[allow(non_snake_case, dead_code)]
    pub fn decode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Result<Vec<u8>, DecodeError> {
        let input_bytes = input.as_ref();
        let input_len: usize = input_bytes.len();
        let mut real_len = 0;
        if input_len == 0 {
            return Ok(Vec::new());
        }

        /* First pass: check for validity and get output length */
        for c in input_bytes.iter().take(input_len) {
            // skip space
            let C1 = (*c) as char;
            if C1 == ' ' || C1 == '\t' || C1 == '\r' || C1 == '\n' {
                continue;
            }

            real_len += 1;
        }

        let mut ret: Vec<u8> = Vec::with_capacity((real_len / 4 + 1) * 3);
        let mut x: u32 = 0;
        let mut n: usize = 0;
        let mut block_len: i32 = 3;

        for (i, c) in input_bytes.iter().enumerate().take(input_len) {
            // skip space
            let C1 = (*c) as char;
            if C1 == ' ' || C1 == '\t' || C1 == '\r' || C1 == '\n' {
                continue;
            }

            let C1IDX = C1 as usize;
            if C1IDX > 127 {
                return Err(DecodeError {
                    message: format!("Charector at {} is invalid, not ascii", i),
                    position: i,
                });
            }

            if C1 != '\0' && C1 == self.padding_char {
                block_len -= 1;
                if block_len < 1 {
                    return Err(DecodeError {
                        message: format!("There are too many padding charector at {}", i),
                        position: i,
                    });
                }
            } else if self.decode_map[C1IDX] == 127 {
                return Err(DecodeError {
                    message: format!("Charector at {} is invalid, unknown charector", i),
                    position: i,
                });
            }

            x = (x << 6) | ((self.decode_map[C1IDX] & 0x3F) as u32);

            n += 1;
            if n == 4 {
                n = 0;
                if block_len > 0 {
                    ret.push(((x >> 16) & 0xFF) as u8);
                }

                if block_len > 1 {
                    ret.push(((x >> 8) & 0xFF) as u8);
                }

                if block_len > 2 {
                    ret.push((x & 0xFF) as u8);
                }
            }
        }

        // no padding, the tail code
        if n == 2 {
            ret.push(((x >> 4) & 0xFF) as u8);
        } else if n == 3 {
            ret.push(((x >> 10) & 0xFF) as u8);
            ret.push(((x >> 2) & 0xFF) as u8);
        }

        Ok(ret)
    }
}

#[allow(dead_code)]
pub const STANDARD: Engine = Engine {
    encode_map: &[
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    ],
    decode_map: &[
        127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
        127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
        127, 127, 127, 127, 127, 127, 127, 62, 127, 127, 127, 63, 52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, 127, 127, 127, 127, 127, 127, 127, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 127, 127, 127, 127, 127, 127, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
        127, 127, 127, 127, 127,
    ],
    padding_char: '=',
};

#[allow(dead_code)]
pub const STANDARD_UTF7: Engine = Engine {
    encode_map: STANDARD.encode_map,
    decode_map: STANDARD.decode_map,
    padding_char: '\0',
};

#[cfg(test)]
mod tests {

    use super::*;

    const BASE64_TEST_DEC: &[u8; 64] = &[
        0x24u8, 0x48, 0x6E, 0x56, 0x87, 0x62, 0x5A, 0xBD, 0xBF, 0x17, 0xD9, 0xA2, 0xC4, 0x17, 0x1A,
        0x01, 0x94, 0xED, 0x8F, 0x1E, 0x11, 0xB3, 0xD7, 0x09, 0x0C, 0xB6, 0xE9, 0x10, 0x6F, 0x22,
        0xEE, 0x13, 0xCA, 0xB3, 0x07, 0x05, 0x76, 0xC9, 0xFA, 0x31, 0x6C, 0x08, 0x34, 0xFF, 0x8D,
        0xC2, 0x6C, 0x38, 0x00, 0x43, 0xE9, 0x54, 0x97, 0xAF, 0x50, 0x4B, 0xD1, 0x41, 0xBA, 0x95,
        0x31, 0x5A, 0x0B, 0x97,
    ];

    const BASE64_TEST_ENC_STANDARD: &str =
        "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==";

    const BASE64_TEST_ENC_UTF7: &str =
        "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw";

    #[test]
    fn encode_standard() {
        assert_eq!(
            STANDARD.encode(BASE64_TEST_DEC.as_ref()).unwrap(),
            BASE64_TEST_ENC_STANDARD
        );
    }

    #[test]
    fn decode_standard() {
        let dec = STANDARD
            .decode(BASE64_TEST_ENC_STANDARD.as_bytes())
            .unwrap();
        assert_eq!(hex::encode(&dec), hex::encode(BASE64_TEST_DEC.as_ref()));
    }

    #[test]
    fn encode_utf7() {
        assert_eq!(
            STANDARD_UTF7.encode(BASE64_TEST_DEC.as_ref()).unwrap(),
            BASE64_TEST_ENC_UTF7
        );
    }

    #[test]
    fn decode_utf7() {
        let dec = STANDARD_UTF7
            .decode(BASE64_TEST_ENC_UTF7.as_bytes())
            .unwrap();
        assert_eq!(hex::encode(&dec), hex::encode(BASE64_TEST_DEC.as_ref()));
    }

    #[test]
    fn encode_standard_nopading() {
        assert_eq!(
            STANDARD_UTF7.encode("any carnal pleas".as_bytes()).unwrap(),
            "YW55IGNhcm5hbCBwbGVhcw"
        );
        assert_eq!(
            STANDARD_UTF7
                .encode("any carnal pleasu".as_bytes())
                .unwrap(),
            "YW55IGNhcm5hbCBwbGVhc3U"
        );
        assert_eq!(
            STANDARD_UTF7
                .encode("any carnal pleasur".as_bytes())
                .unwrap(),
            "YW55IGNhcm5hbCBwbGVhc3Vy"
        );
    }

    #[test]
    fn decode_standard_nopading() {
        assert_eq!(
            String::from_utf8(
                STANDARD_UTF7
                    .decode("YW55IGNhcm5hbCBwbGVhcw".as_bytes())
                    .unwrap()
            )
            .unwrap(),
            "any carnal pleas"
        );

        assert_eq!(
            String::from_utf8(
                STANDARD_UTF7
                    .decode("YW55IGNhcm5hbCBwbGVhc3U".as_bytes())
                    .unwrap()
            )
            .unwrap(),
            "any carnal pleasu"
        );

        assert_eq!(
            String::from_utf8(
                STANDARD_UTF7
                    .decode("YW55IGNhcm5hbCBwbGVhc3Vy".as_bytes())
                    .unwrap()
            )
            .unwrap(),
            "any carnal pleasur"
        );
    }
}
