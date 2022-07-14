//! DER / ASN.1 support for JPKI functions.

use std::borrow::Cow;

/// Stateful, simple and customised DER / ASN.1 reader for JPKI.
pub struct Reader<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new reader from the buffer.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Reads data of specified size without seeking the cursor.
    pub fn peek(&self, length: usize) -> &'a [u8] {
        &self.buffer[self.cursor..self.cursor + length]
    }

    /// Seeks the cursor without reading data
    pub fn seek(&mut self, length: usize) {
        self.cursor += length;
    }

    /// Reads a next octet and seeks the cursor.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u8 {
        let byte = self.buffer[self.cursor];
        self.seek(1);
        byte
    }

    /// Reads data of specified size and seeks the cursor.
    /// Short version of `self.peek` + `self.seek`
    pub fn read(&mut self, length: usize) -> &'a [u8] {
        let bytes = self.peek(length);
        self.seek(length);
        bytes
    }

    /// Reads the length of data at the current position, seeking the cursor.
    pub fn read_length(&mut self) -> usize {
        if self.next() & 0x1f == 0x1f {
            self.next();
        }

        let head = self.next() as usize;
        if head & 0x80 == 0 {
            head
        } else {
            let mut size = 0usize;
            for _ in 0..(head & 0x7f) {
                size <<= 8;
                size |= self.next() as usize
            }

            size
        }
    }

    /// Reads the data at the current position automatically, seeking the cursor.
    /// Short version of `self.read(self.read_length())`.
    pub fn read_auto(&mut self) -> &'a [u8] {
        let length = self.read_length();

        self.read(length)
    }

    /// Read a `Cow<'a, str>' at the current position, seeking the cursor.
    pub fn read_str(&mut self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.read_auto())
    }

    /// Read a `String` at the current position, seeking the cursor.
    pub fn read_string(&mut self) -> String {
        self.read_str().to_string()
    }

    /// Runs the closure in the sequence at the current position, seeking the cursor.
    pub fn in_sequence<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut Self) -> T,
    {
        f(&mut Self::new(self.read_auto()))
    }
}

/// Calculates entire size of the payload from the partial buffer of them.
pub fn entire_size_from_partial(header: &[u8]) -> usize {
    let mut reader = Reader::new(header);

    reader.read_length() + reader.cursor
}
