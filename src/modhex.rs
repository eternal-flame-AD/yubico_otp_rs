const ALPHABET: [char; 16] = [
    'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v',
];

/// A ModHex string.
pub struct ModHex<'a>(&'a str);

/// Modhex decoder.
pub struct ModHexDecoder<T>
where
    T: Iterator<Item = char>,
{
    inner: T,
}

impl<T> ModHexDecoder<T>
where
    T: Iterator<Item = char>,
{
    /// Create a new ModHex decoder from an iterator of chars.
    pub fn new(inner: T) -> ModHexDecoder<T> {
        ModHexDecoder::<T> { inner }
    }
}

impl<T> Iterator for ModHexDecoder<T>
where
    T: Iterator<Item = char>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let c_high = self.inner.next()?;
        let c_low = self.inner.next()?;
        let high_idx = ALPHABET.iter().position(|&c| c == c_high)? as u8;
        let low_idx = ALPHABET.iter().position(|&c| c == c_low)? as u8;
        Some((high_idx << 4) | low_idx)
    }
}

/// Modhex encoder.
pub struct ModHexEncoder<T>
where
    T: Iterator<Item = u8>,
{
    inner: T,
    buf: Option<u8>,
}

impl<T> ModHexEncoder<T>
where
    T: Iterator<Item = u8>,
{
    /// Create a new ModHex encoder from an iterator of bytes.
    pub fn new(inner: T) -> ModHexEncoder<T> {
        ModHexEncoder::<T> { inner, buf: None }
    }
}

impl<T> Iterator for ModHexEncoder<T>
where
    T: Iterator<Item = u8>,
{
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(c) = self.buf {
            self.buf = None;
            return Some(ALPHABET[c as usize]);
        }
        let idx = self.inner.next()?;
        let high = idx >> 4;
        let low = idx & 0xf;
        self.buf = Some(low);
        Some(ALPHABET[high as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_modhex_decode() {
        let input = "clrrliejedfg";
        let output = ModHexDecoder::new(input.chars()).collect::<Vec<u8>>();
        assert_eq!(output, vec![0x0a, 0xcc, 0xa7, 0x38, 0x32, 0x45])
    }

    #[test]
    fn test_mdodhex_serdes() {
        for len in 0..=255 {
            let mut input = vec![0; len];
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut input);

            let encoded = ModHexEncoder::new(input.iter().copied()).collect::<String>();
            let decoded = ModHexDecoder::new(encoded.chars()).collect::<Vec<u8>>();
            assert_eq!(input, decoded);
        }
    }
}
