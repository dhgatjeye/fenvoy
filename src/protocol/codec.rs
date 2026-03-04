use crate::error::{FenvoyError, Result};
use crate::protocol::MAX_RECORD_PAYLOAD;

pub fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}
pub fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn write_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let len = data.len();
    if len > u32::MAX as usize {
        return Err(FenvoyError::MessageTooLarge {
            size: len,
            max: u32::MAX as usize,
        });
    }
    write_u32(buf, len as u32);
    buf.extend_from_slice(data);
    Ok(())
}

pub fn write_raw(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(data);
}

pub fn write_str(buf: &mut Vec<u8>, s: &str) -> Result<()> {
    let len = s.len();
    if len > u16::MAX as usize {
        return Err(FenvoyError::MessageTooLarge {
            size: len,
            max: u16::MAX as usize,
        });
    }
    write_u16(buf, len as u16);
    buf.extend_from_slice(s.as_bytes());
    Ok(())
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn peek_u8(&self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(FenvoyError::InvalidMessage(
                "unexpected end of message".into(),
            ));
        }
        Ok(self.data[self.pos])
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(FenvoyError::InvalidMessage(
                "unexpected end of message".into(),
            ));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(FenvoyError::InvalidMessage(
                "unexpected end of message".into(),
            ));
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(FenvoyError::InvalidMessage(
                "unexpected end of message".into(),
            ));
        }
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        if self.remaining() < 8 {
            return Err(FenvoyError::InvalidMessage(
                "unexpected end of message".into(),
            ));
        }
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        if self.remaining() < 8 {
            return Err(FenvoyError::InvalidMessage(
                "unexpected end of message".into(),
            ));
        }
        let v = i64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.remaining() < len {
            return Err(FenvoyError::InvalidMessage(format!(
                "need {len} bytes but only {} remaining",
                self.remaining()
            )));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        if len > MAX_RECORD_PAYLOAD {
            return Err(FenvoyError::MessageTooLarge {
                size: len,
                max: MAX_RECORD_PAYLOAD,
            });
        }
        self.read_exact(len)
    }

    pub fn read_str(&mut self) -> Result<&'a str> {
        let len = self.read_u16()? as usize;
        let bytes = self.read_exact(len)?;
        std::str::from_utf8(bytes)
            .map_err(|_| FenvoyError::InvalidMessage("invalid UTF-8 in string field".into()))
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_exact(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u8() {
        let mut buf = Vec::new();
        write_u8(&mut buf, 42);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_u8().unwrap(), 42);
        assert!(r.is_empty());
    }

    #[test]
    fn roundtrip_u16() {
        let mut buf = Vec::new();
        write_u16(&mut buf, 0xBEEF);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_u16().unwrap(), 0xBEEF);
    }

    #[test]
    fn roundtrip_u32() {
        let mut buf = Vec::new();
        write_u32(&mut buf, 0xDEAD_BEEF);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn roundtrip_u64() {
        let mut buf = Vec::new();
        write_u64(&mut buf, 0x0102_0304_0506_0708);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_u64().unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn roundtrip_i64() {
        let mut buf = Vec::new();
        write_i64(&mut buf, -1234567890);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_i64().unwrap(), -1234567890);
    }

    #[test]
    fn roundtrip_bytes() {
        let mut buf = Vec::new();
        write_bytes(&mut buf, b"hello").unwrap();
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_bytes().unwrap(), b"hello");
    }

    #[test]
    fn roundtrip_str() {
        let mut buf = Vec::new();
        write_str(&mut buf, "fenvoy 🚀").unwrap();
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_str().unwrap(), "fenvoy 🚀");
    }

    #[test]
    fn roundtrip_array() {
        let mut buf = Vec::new();
        write_raw(&mut buf, &[1, 2, 3, 4]);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_array::<4>().unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn read_past_end_fails() {
        let buf = [0u8; 2];
        let mut r = Reader::new(&buf);
        assert!(r.read_u32().is_err());
    }

    #[test]
    fn multiple_fields() {
        let mut buf = Vec::new();
        write_u8(&mut buf, 1);
        write_u32(&mut buf, 100);
        write_str(&mut buf, "test").unwrap();
        write_u64(&mut buf, 9999);

        let mut r = Reader::new(&buf);
        assert_eq!(r.read_u8().unwrap(), 1);
        assert_eq!(r.read_u32().unwrap(), 100);
        assert_eq!(r.read_str().unwrap(), "test");
        assert_eq!(r.read_u64().unwrap(), 9999);
        assert!(r.is_empty());
    }

    #[test]
    fn read_bytes_rejects_oversized_length() {
        let mut buf = Vec::new();
        write_u32(&mut buf, 0xFFFF_FFFF);
        buf.extend_from_slice(&[0u8; 16]);

        let mut r = Reader::new(&buf);
        let err = r.read_bytes().unwrap_err();
        match err {
            FenvoyError::MessageTooLarge { size, max } => {
                assert_eq!(size, 0xFFFF_FFFF_usize);
                assert_eq!(max, MAX_RECORD_PAYLOAD);
            }
            _ => panic!("expected MessageTooLarge, got {err:?}"),
        }
    }

    #[test]
    fn write_str_rejects_oversized() {
        let long = "x".repeat(u16::MAX as usize + 1);
        let mut buf = Vec::new();
        let err = write_str(&mut buf, &long).unwrap_err();
        match err {
            FenvoyError::MessageTooLarge { size, max } => {
                assert_eq!(size, u16::MAX as usize + 1);
                assert_eq!(max, u16::MAX as usize);
            }
            _ => panic!("expected MessageTooLarge, got {err:?}"),
        }
    }

    #[test]
    fn write_str_accepts_max_length() {
        let exact = "a".repeat(u16::MAX as usize);
        let mut buf = Vec::new();
        write_str(&mut buf, &exact).unwrap();
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_str().unwrap().len(), u16::MAX as usize);
    }
}
