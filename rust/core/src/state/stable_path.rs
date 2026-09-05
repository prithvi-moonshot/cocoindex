use crate::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt::Write as FmtWrite, io::Write};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StableKey {
    Null,
    Symbol(Arc<str>),
    Bool(bool),
    Int(i64),
    Str(Arc<str>),
    Bytes(Arc<[u8]>),
    Uuid(uuid::Uuid),
    Array(Arc<[StableKey]>),
    Fingerprint(utils::fingerprint::Fingerprint),
}

impl Serialize for StableKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self {
            StableKey::Null => serializer.serialize_unit(),
            StableKey::Bool(b) => serializer.serialize_bool(*b),
            StableKey::Int(i) => serializer.serialize_i64(*i),
            StableKey::Str(s) => serializer.serialize_str(s),
            StableKey::Bytes(b) => serializer.serialize_bytes(b.as_ref()),
            StableKey::Uuid(u) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("uuid", u)?;
                map.end()
            }
            StableKey::Array(a) => a.as_ref().serialize(serializer),
            StableKey::Fingerprint(fp) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("fp", fp)?;
                map.end()
            }
            StableKey::Symbol(s) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("sym", s.as_ref())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for StableKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Null(()),
            Bool(bool),
            Int(i64),
            Str(String),
            // Intentionally before Array to preserve StableKey::Bytes roundtrip in formats
            // (like JSON) where bytes can be represented as a sequence of integers.
            // `serde_bytes` makes this consume a native byte string too (msgpack
            // `bin`, the state-store format) — a plain `Vec<u8>` only deserializes
            // via `deserialize_seq`, so a `bin` would fail to match any variant.
            #[serde(with = "serde_bytes")]
            Bytes(Vec<u8>),
            Uuid {
                uuid: uuid::Uuid,
            },
            Fp {
                fp: utils::fingerprint::Fingerprint,
            },
            Sym {
                sym: String,
            },
            Array(Vec<Repr>),
        }

        impl Repr {
            fn into_stable_key(self) -> StableKey {
                match self {
                    Repr::Null(()) => StableKey::Null,
                    Repr::Bool(b) => StableKey::Bool(b),
                    Repr::Int(i) => StableKey::Int(i),
                    Repr::Str(s) => StableKey::Str(Arc::from(s)),
                    Repr::Bytes(b) => StableKey::Bytes(Arc::from(b)),
                    Repr::Uuid { uuid } => StableKey::Uuid(uuid),
                    Repr::Fp { fp } => StableKey::Fingerprint(fp),
                    Repr::Sym { sym } => StableKey::Symbol(Arc::from(sym)),
                    Repr::Array(items) => StableKey::Array(Arc::from(
                        items
                            .into_iter()
                            .map(Repr::into_stable_key)
                            .collect::<Vec<_>>(),
                    )),
                }
            }
        }

        Ok(Repr::deserialize(deserializer)?.into_stable_key())
    }
}

/// Whether a symbol name can be rendered without quotes, i.e. it can't be
/// confused with the path/array syntax around it (`/`, `,`, `]`) or with a
/// quoted form. Anything else is rendered as `@"..."`.
fn is_bare_symbol_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn write_quoted_str(f: &mut std::fmt::Formatter<'_>, s: &str) -> std::fmt::Result {
    f.write_char('"')?;
    for c in s.chars() {
        for esc in c.escape_default() {
            f.write_char(esc)?;
        }
    }
    f.write_char('"')
}

impl std::fmt::Display for StableKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StableKey::Null => write!(f, "null"),
            StableKey::Bool(b) => write!(f, "{}", b),
            StableKey::Int(i) => write!(f, "{}", i),
            StableKey::Str(s) => write_quoted_str(f, s),
            StableKey::Bytes(b) => {
                f.write_str("b\"")?;
                for &byte in b.iter() {
                    for esc in std::ascii::escape_default(byte) {
                        f.write_char(esc as char)?;
                    }
                }
                f.write_char('"')
            }
            StableKey::Uuid(u) => write!(f, "{}", u.to_string()),
            StableKey::Array(a) => {
                f.write_char('[')?;
                for (i, part) in a.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    part.fmt(f)?;
                }
                f.write_char(']')
            }
            StableKey::Fingerprint(fp) => write!(f, "{fp}"),
            StableKey::Symbol(s) => {
                f.write_char('@')?;
                if is_bare_symbol_name(s) {
                    f.write_str(s)
                } else {
                    write_quoted_str(f, s)
                }
            }
        }
    }
}

impl storekey::Encode for StableKey {
    fn encode<W: Write>(&self, e: &mut storekey::Writer<W>) -> Result<(), storekey::EncodeError> {
        match self {
            StableKey::Null => {
                e.write_u8(2)?;
            }
            StableKey::Symbol(s) => {
                e.write_u8(3)?;
                e.write_slice(s.as_bytes())?;
            }
            StableKey::Bool(false) => {
                e.write_u8(4)?;
                e.write_u8(0)?;
            }
            StableKey::Bool(true) => {
                e.write_u8(4)?;
                e.write_u8(1)?;
            }
            StableKey::Int(i) => {
                e.write_u8(5)?;
                e.write_i64(*i)?;
            }
            StableKey::Str(s) => {
                e.write_u8(6)?;
                e.write_slice(s.as_bytes())?;
            }
            StableKey::Bytes(b) => {
                e.write_u8(7)?;
                e.write_slice(b.as_ref())?;
            }
            StableKey::Uuid(u) => {
                e.write_u8(8)?;
                e.write_array(*u.as_bytes())?;
            }
            StableKey::Array(a) => {
                e.write_u8(9)?;
                storekey::Encode::encode(a.as_ref(), e)?;
            }
            StableKey::Fingerprint(fp) => {
                e.write_u8(10)?;
                storekey::Encode::encode(fp, e)?;
            }
        }
        Ok(())
    }
}

impl storekey::Decode for StableKey {
    fn decode<D: std::io::BufRead>(
        d: &mut storekey::Reader<D>,
    ) -> Result<Self, storekey::DecodeError> {
        match d.read_u8()? {
            2 => Ok(StableKey::Null),
            3 => Ok(StableKey::Symbol(d.read_string()?.into())),
            4 => Ok(StableKey::Bool(d.read_u8()? != 0)),
            5 => Ok(StableKey::Int(d.read_i64()?)),
            6 => Ok(StableKey::Str(d.read_string()?.into())),
            7 => Ok(StableKey::Bytes(Arc::from(d.read_vec()?))),
            8 => {
                let bytes: [u8; 16] = d.read_array()?;
                Ok(StableKey::Uuid(uuid::Uuid::from_bytes(bytes)))
            }
            9 => {
                let v: Vec<StableKey> = storekey::Decode::decode(d)?;
                Ok(StableKey::Array(Arc::from(v)))
            }
            10 => {
                let fp: utils::fingerprint::Fingerprint = storekey::Decode::decode(d)?;
                Ok(StableKey::Fingerprint(fp))
            }
            _ => Err(storekey::DecodeError::InvalidFormat),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct StablePathRef<'a>(pub &'a [StableKey]);

impl<'a> std::fmt::Display for StablePathRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_char('/');
        }
        for part in self.0.iter() {
            f.write_str("/")?;
            part.fmt(f)?;
        }
        Ok(())
    }
}

impl<'a> From<&'a [StableKey]> for StablePathRef<'a> {
    fn from(value: &'a [StableKey]) -> Self {
        StablePathRef(value)
    }
}

impl<'a> std::ops::Deref for StablePathRef<'a> {
    type Target = [StableKey];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'p> StablePathRef<'p> {
    pub fn strip_parent(&self, parent: StablePathRef) -> Result<Self> {
        if self.0.len() < parent.0.len() || &self.0[..parent.0.len()] != parent.0 {
            internal_bail!("Path {self} is not a child of parent {parent}");
        }
        Ok(StablePathRef(&self.0[parent.0.len()..]))
    }

    pub fn concat(&self, other: StablePathRef) -> StablePath {
        StablePath(self.0.iter().chain(other.0.iter()).cloned().collect())
    }

    pub fn concat_part(&self, part: StableKey) -> StablePath {
        StablePath(
            self.0
                .iter()
                .cloned()
                .chain(std::iter::once(part))
                .collect(),
        )
    }

    pub fn split_parent(&self) -> Option<(StablePathRef<'p>, &'p StableKey)> {
        self.0
            .split_last()
            .map(|(last, parent)| (StablePathRef(parent), last))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StablePath(pub Arc<[StableKey]>);

impl storekey::Encode for StablePath {
    fn encode<W: Write>(&self, e: &mut storekey::Writer<W>) -> Result<(), storekey::EncodeError> {
        storekey::Encode::encode(self.0.as_ref(), e)
    }
}

impl storekey::Decode for StablePath {
    fn decode<D: std::io::BufRead>(
        d: &mut storekey::Reader<D>,
    ) -> Result<Self, storekey::DecodeError> {
        let items: Vec<StableKey> = storekey::Decode::decode(d)?;
        Ok(StablePath(Arc::from(items)))
    }
}

static ROOT_PATH: LazyLock<StablePath> = LazyLock::new(|| StablePath(Arc::new([])));

impl StablePath {
    pub fn root() -> Self {
        ROOT_PATH.clone()
    }

    pub fn concat_part(&self, part: StableKey) -> Self {
        self.as_ref().concat_part(part)
    }

    pub fn concat(&self, other: StablePathRef) -> StablePath {
        self.as_ref().concat(other)
    }

    pub fn as_ref<'a>(&'a self) -> StablePathRef<'a> {
        StablePathRef(self.0.as_ref())
    }
}

impl<'a> From<StablePathRef<'a>> for StablePath {
    fn from(value: StablePathRef<'a>) -> Self {
        StablePath(value.0.to_owned().into())
    }
}

impl std::fmt::Display for StablePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        StablePathRef(self.0.as_ref()).fmt(f)
    }
}

impl std::ops::Deref for StablePath {
    type Target = [StableKey];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> std::borrow::Borrow<[StableKey]> for StablePath {
    fn borrow(&self) -> &[StableKey] {
        &self.0
    }
}

/// Parser for the textual form that [`StableKey`] and [`StablePath`] render
/// through `Display`, so a path printed by the CLI can be fed back in.
///
/// Every key type renders with a distinguishing marker — `"…"` for strings,
/// `b"…"` for bytes, `@…` for symbols, `#…` for fingerprints, `[…]` for
/// arrays, and bare `null`/`true`/`false`/integer/UUID tokens for the rest —
/// so the grammar stays unambiguous and this parser is the exact inverse of
/// `Display`.
struct StablePathParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> StablePathParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += c.len_utf8();
            true
        } else {
            false
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Parse `/`-separated parts. The leading `/` is optional so both the
    /// rendered form (`/@files/"a.md"`) and a bare relative form parse.
    fn parse_path(&mut self) -> Result<StablePath> {
        let mut parts = Vec::new();
        self.eat('/');
        if self.at_end() {
            return Ok(StablePath(Arc::from(parts)));
        }
        loop {
            parts.push(self.parse_key()?);
            if !self.eat('/') {
                break;
            }
        }
        if !self.at_end() {
            client_bail!(
                "Unexpected character {:?} at position {} of stable path {:?}",
                self.peek().unwrap_or_default(),
                self.pos,
                self.input
            );
        }
        Ok(StablePath(Arc::from(parts)))
    }

    fn parse_key(&mut self) -> Result<StableKey> {
        match self.peek() {
            Some('"') => Ok(StableKey::Str(Arc::from(self.parse_quoted_str()?))),
            Some('b') if self.input[self.pos..].starts_with("b\"") => {
                self.pos += 1;
                Ok(StableKey::Bytes(Arc::from(self.parse_quoted_bytes()?)))
            }
            Some('@') => {
                self.pos += 1;
                let name = if self.peek() == Some('"') {
                    self.parse_quoted_str()?
                } else {
                    let bare = self.take_token();
                    if !is_bare_symbol_name(bare) {
                        client_bail!(
                            "Invalid symbol name {:?} at position {} of stable path {:?}; \
                             quote it as @\"...\"",
                            bare,
                            self.pos,
                            self.input
                        );
                    }
                    bare.to_string()
                };
                Ok(StableKey::Symbol(Arc::from(name)))
            }
            Some('[') => {
                self.pos += 1;
                let mut items = Vec::new();
                if !self.eat(']') {
                    loop {
                        items.push(self.parse_key()?);
                        if self.eat(']') {
                            break;
                        }
                        if !self.eat(',') {
                            client_bail!(
                                "Expected ',' or ']' at position {} of stable path {:?}",
                                self.pos,
                                self.input
                            );
                        }
                    }
                }
                Ok(StableKey::Array(Arc::from(items)))
            }
            Some('#') => {
                self.pos += 1;
                let token = self.take_token();
                let fp = parse_fingerprint_hex(token).ok_or_else(|| {
                    client_error!(
                        "Invalid fingerprint {:?} in stable path {:?}; expected 32 hex digits",
                        token,
                        self.input
                    )
                })?;
                Ok(StableKey::Fingerprint(fp))
            }
            _ => {
                let start = self.pos;
                let token = self.take_token();
                if token == "null" {
                    Ok(StableKey::Null)
                } else if token == "true" {
                    Ok(StableKey::Bool(true))
                } else if token == "false" {
                    Ok(StableKey::Bool(false))
                } else if let Ok(i) = token.parse::<i64>() {
                    Ok(StableKey::Int(i))
                } else if let Ok(u) = uuid::Uuid::parse_str(token) {
                    Ok(StableKey::Uuid(u))
                } else if token.is_empty() {
                    client_bail!(
                        "Empty key at position {} of stable path {:?}",
                        start,
                        self.input
                    )
                } else {
                    client_bail!(
                        "Cannot interpret {:?} at position {} of stable path {:?} as a key; \
                         write \"{}\" for a string key or @{} for a symbol key",
                        token,
                        start,
                        self.input,
                        token,
                        token
                    )
                }
            }
        }
    }

    /// Consume characters up to the next structural delimiter (`/`, `,`, `]`).
    fn take_token(&mut self) -> &'a str {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if matches!(c, '/' | ',' | ']') {
                break;
            }
            self.pos += c.len_utf8();
        }
        &self.input[start..self.pos]
    }

    /// Parse a `"..."` literal escaped by `char::escape_default` (the escaping
    /// `Display` applies to strings and non-bare symbol names).
    fn parse_quoted_str(&mut self) -> Result<String> {
        self.expect_quote()?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None => client_bail!("Unterminated quoted string in stable path {:?}", self.input),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('\\') => out.push('\\'),
                    Some('\'') => out.push('\''),
                    Some('"') => out.push('"'),
                    Some('0') => out.push('\0'),
                    Some('u') => out.push(self.parse_unicode_escape()?),
                    other => client_bail!(
                        "Invalid escape \\{} in stable path {:?}",
                        other.unwrap_or_default(),
                        self.input
                    ),
                },
                Some(c) => out.push(c),
            }
        }
    }

    /// Parse the `"..."` part of a `b"..."` literal, escaped by
    /// `std::ascii::escape_default`.
    fn parse_quoted_bytes(&mut self) -> Result<Vec<u8>> {
        self.expect_quote()?;
        let mut out = Vec::new();
        loop {
            match self.bump() {
                None => client_bail!("Unterminated byte string in stable path {:?}", self.input),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('n') => out.push(b'\n'),
                    Some('r') => out.push(b'\r'),
                    Some('t') => out.push(b'\t'),
                    Some('\\') => out.push(b'\\'),
                    Some('\'') => out.push(b'\''),
                    Some('"') => out.push(b'"'),
                    Some('0') => out.push(0),
                    Some('x') => out.push(self.parse_hex_byte()?),
                    other => client_bail!(
                        "Invalid escape \\{} in stable path {:?}",
                        other.unwrap_or_default(),
                        self.input
                    ),
                },
                // `escape_default` only emits ASCII, so anything else is a
                // literal byte the writer passed through unescaped.
                Some(c) if c.is_ascii() => out.push(c as u8),
                Some(c) => client_bail!(
                    "Non-ASCII character {:?} in byte string of stable path {:?}",
                    c,
                    self.input
                ),
            }
        }
    }

    fn expect_quote(&mut self) -> Result<()> {
        if !self.eat('"') {
            client_bail!(
                "Expected '\"' at position {} of stable path {:?}",
                self.pos,
                self.input
            );
        }
        Ok(())
    }

    fn parse_unicode_escape(&mut self) -> Result<char> {
        if !self.eat('{') {
            client_bail!(
                "Expected '{{' after \\u at position {} of stable path {:?}",
                self.pos,
                self.input
            );
        }
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
            self.pos += 1;
        }
        let digits = &self.input[start..self.pos];
        if !self.eat('}') {
            client_bail!(
                "Unterminated \\u escape at position {} of stable path {:?}",
                self.pos,
                self.input
            );
        }
        u32::from_str_radix(digits, 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| {
                client_error!(
                    "Invalid unicode escape \\u{{{}}} in stable path {:?}",
                    digits,
                    self.input
                )
            })
    }

    fn parse_hex_byte(&mut self) -> Result<u8> {
        let start = self.pos;
        for _ in 0..2 {
            match self.peek() {
                Some(c) if c.is_ascii_hexdigit() => self.pos += 1,
                _ => client_bail!(
                    "Expected two hex digits after \\x at position {} of stable path {:?}",
                    self.pos,
                    self.input
                ),
            }
        }
        Ok(
            u8::from_str_radix(&self.input[start..self.pos], 16).map_err(|e| {
                client_error!("Invalid \\x escape in stable path {:?}: {e}", self.input)
            })?,
        )
    }
}

/// Decode the 32 hex digits that follow the `#` in a rendered fingerprint.
fn parse_fingerprint_hex(token: &str) -> Option<utils::fingerprint::Fingerprint> {
    if token.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(token.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(utils::fingerprint::Fingerprint(bytes))
}

impl std::str::FromStr for StablePath {
    type Err = utils::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        StablePathParser::new(s.trim()).parse_path()
    }
}

impl StablePath {
    /// Parse a path from the textual form rendered by [`Display`].
    ///
    /// [`Display`]: std::fmt::Display
    pub fn parse(s: &str) -> Result<Self> {
        s.parse()
    }
}

#[derive(Debug, Default)]
pub struct StablePathPrefix<'a>(StablePathRef<'a>);

impl<'a> storekey::Encode for StablePathPrefix<'a> {
    fn encode<W: Write>(&self, e: &mut storekey::Writer<W>) -> Result<(), storekey::EncodeError> {
        for part in self.0.iter() {
            part.encode(e)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip<T>(value: &T) -> T
    where
        T: storekey::Encode + storekey::Decode + PartialEq + std::fmt::Debug,
    {
        let buf = storekey::encode_vec(value).expect("encode");
        let decoded: T = storekey::decode(Cursor::new(&buf)).expect("decode");
        decoded
    }

    #[test]
    fn stable_key_roundtrip() {
        let uuid = uuid::Uuid::from_bytes([3u8; 16]);
        let fp = utils::fingerprint::Fingerprint([7u8; 16]);
        let cases = vec![
            StableKey::Null,
            StableKey::Bool(false),
            StableKey::Bool(true),
            StableKey::Int(0),
            StableKey::Int(-1),
            StableKey::Int(i64::MIN / 2),
            StableKey::Int(i64::MAX / 2),
            StableKey::Str(Arc::from("hello")),
            StableKey::Str(Arc::from("nul\0inside")),
            StableKey::Bytes(Arc::from(&b"bytes\x00with\x01escapes"[..])),
            StableKey::Uuid(uuid),
            StableKey::Array(Arc::from([
                StableKey::Int(1),
                StableKey::Str(Arc::from("a")),
                StableKey::Bytes(Arc::from(&b"\0"[..])),
            ])),
            StableKey::Fingerprint(fp),
            StableKey::Symbol(Arc::from("cocoindex/setup")),
        ];

        for original in cases {
            let decoded = roundtrip(&original);
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn stable_path_roundtrip() {
        let path = StablePath(Arc::from(vec![
            StableKey::Int(42),
            StableKey::Str(Arc::from("part")),
            StableKey::Bytes(Arc::from(&b"\0term"[..])),
        ]));
        let decoded = roundtrip(&path);
        assert_eq!(decoded, path);

        let empty = StablePath::root();
        let decoded_empty = roundtrip(&empty);
        assert_eq!(decoded_empty, empty);
    }

    /// One key of every `StableKey` variant, including cross-type twins whose
    /// *values* look like another variant's rendering.
    fn representative_keys() -> Vec<StableKey> {
        let uuid = uuid::Uuid::from_bytes([3u8; 16]);
        let fp = utils::fingerprint::Fingerprint([7u8; 16]);
        vec![
            StableKey::Null,
            StableKey::Bool(true),
            StableKey::Bool(false),
            StableKey::Int(0),
            StableKey::Int(13),
            StableKey::Int(-42),
            StableKey::Int(i64::MIN),
            StableKey::Int(i64::MAX),
            StableKey::Str(Arc::from("rfc8259.md")),
            // Strings that would break a naive split on '/' or on quotes.
            StableKey::Str(Arc::from("a/b/c")),
            StableKey::Str(Arc::from("with \"quotes\" and \\ backslash")),
            StableKey::Str(Arc::from("nul\0and\ttabs\n")),
            StableKey::Str(Arc::from("café ☕")),
            StableKey::Str(Arc::from("")),
            // Strings whose text is exactly some other variant's rendering.
            StableKey::Str(Arc::from("null")),
            StableKey::Str(Arc::from("true")),
            StableKey::Str(Arc::from("13")),
            StableKey::Str(Arc::from("@process_files")),
            StableKey::Str(Arc::from("[13,null]")),
            StableKey::Str(Arc::from(fp.to_string())),
            StableKey::Str(Arc::from(uuid.to_string())),
            StableKey::Bytes(Arc::from(&b"bytes\x00with\x01escapes/and\"quote"[..])),
            // Bytes whose text is a string key's rendering.
            StableKey::Bytes(Arc::from(&b"13"[..])),
            StableKey::Bytes(Arc::from(&b""[..])),
            StableKey::Uuid(uuid),
            StableKey::Fingerprint(fp),
            StableKey::Symbol(Arc::from("process_files")),
            // Symbols whose name is another variant's rendering.
            StableKey::Symbol(Arc::from("null")),
            StableKey::Symbol(Arc::from("true")),
            StableKey::Symbol(Arc::from("13")),
            // Symbols carrying '/' must stay one part — several internal
            // symbols (e.g. "cocoindex/mount_target") contain one.
            StableKey::Symbol(Arc::from("cocoindex/mount_target")),
            StableKey::Symbol(Arc::from("")),
            StableKey::Array(Arc::from([])),
            StableKey::Array(Arc::from([
                StableKey::Int(13),
                StableKey::Str(Arc::from("a,b]c/d")),
                StableKey::Symbol(Arc::from("sys/state")),
                StableKey::Array(Arc::from([
                    StableKey::Null,
                    StableKey::Bytes(Arc::from(&b"\0"[..])),
                ])),
            ])),
            // An array whose rendering a naive parser could confuse with the
            // single string key that spells the same text.
            StableKey::Array(Arc::from([StableKey::Int(13), StableKey::Null])),
        ]
    }

    /// No two distinct keys may render to the same string — otherwise a path
    /// can't be read back unambiguously, whatever the parser does.
    #[test]
    fn stable_key_renderings_do_not_collide() {
        let keys = representative_keys();
        let mut seen: HashMap<String, StableKey> = HashMap::new();
        for key in keys {
            let rendered = key.to_string();
            if let Some(other) = seen.insert(rendered.clone(), key.clone()) {
                panic!("{other:?} and {key:?} both render as {rendered}");
            }
        }
    }

    /// Every key type must survive `Display` -> `parse`, so a path copied
    /// out of `cocoindex show` can be pasted back in as an argument.
    #[test]
    fn stable_path_display_parse_roundtrip() {
        let keys = representative_keys();

        for key in &keys {
            let path = StablePath(Arc::from(vec![key.clone()]));
            let rendered = path.to_string();
            let parsed = StablePath::parse(&rendered)
                .unwrap_or_else(|e| panic!("parse {rendered:?} failed: {e}"));
            assert_eq!(parsed, path, "roundtrip failed for {rendered}");
        }

        // The whole set as one deep path.
        let path = StablePath(Arc::from(keys));
        assert_eq!(StablePath::parse(&path.to_string()).unwrap(), path);

        // Root.
        assert_eq!(StablePath::parse("/").unwrap(), StablePath::root());
        assert_eq!(StablePath::parse("").unwrap(), StablePath::root());
    }

    #[test]
    fn stable_key_display_is_unambiguous() {
        assert_eq!(
            StablePath(Arc::from(vec![
                StableKey::Symbol(Arc::from("process_files")),
                StableKey::Str(Arc::from("rfc8259.md")),
            ]))
            .to_string(),
            "/@process_files/\"rfc8259.md\""
        );
        // A symbol that isn't a bare token gets quoted, so it stays one segment.
        assert_eq!(
            StableKey::Symbol(Arc::from("cocoindex/mount_target")).to_string(),
            "@\"cocoindex/mount_target\""
        );
    }

    #[test]
    fn stable_path_parse_rejects_ambiguous_input() {
        // A bare word is neither a string nor a symbol — the caller has to say
        // which, instead of it silently becoming a string (issue #2297).
        let err = StablePath::parse("/process_files").unwrap_err().to_string();
        assert!(err.contains("process_files"), "unexpected error: {err}");

        for bad in [
            "/\"unterminated",
            "/b\"unterminated",
            "/[1,2",
            "/#abc",
            "/@bad name",
            "//",
            "/\"a\"x",
        ] {
            assert!(
                StablePath::parse(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn stable_key_serde_json_shape() {
        use serde_json::{Value, json};

        let uuid = uuid::Uuid::from_bytes([3u8; 16]);
        let fp = utils::fingerprint::Fingerprint([7u8; 16]);

        let cases: Vec<(StableKey, Value)> = vec![
            (StableKey::Null, Value::Null),
            (StableKey::Bool(true), json!(true)),
            (StableKey::Int(-7), json!(-7)),
            (StableKey::Str(Arc::from("hi")), json!("hi")),
            (
                StableKey::Bytes(Arc::from(&b"\x00\x01\xff"[..])),
                json!([0, 1, 255]),
            ),
            (StableKey::Uuid(uuid), json!({ "uuid": uuid.to_string() })),
            (
                StableKey::Fingerprint(fp),
                json!({ "fp": serde_json::to_value(fp).expect("fp to value") }),
            ),
            (
                StableKey::Symbol(Arc::from("cocoindex/setup")),
                json!({ "sym": "cocoindex/setup" }),
            ),
            (
                StableKey::Array(Arc::from([
                    StableKey::Int(1),
                    StableKey::Str(Arc::from("a")),
                ])),
                json!([1, "a"]),
            ),
        ];

        for (key, expected) in cases {
            let got = serde_json::to_value(&key).expect("serialize");
            assert_eq!(got, expected);
            let roundtrip: StableKey = serde_json::from_value(got).expect("deserialize");
            assert_eq!(roundtrip, key);
        }
    }

    #[test]
    fn stable_path_serde_json_shape() {
        use serde_json::json;

        let uuid = uuid::Uuid::from_bytes([3u8; 16]);
        let fp = utils::fingerprint::Fingerprint([7u8; 16]);

        let path = StablePath(Arc::from(vec![
            StableKey::Int(42),
            StableKey::Bytes(Arc::from(&b"\0term"[..])),
            StableKey::Uuid(uuid),
            StableKey::Fingerprint(fp),
        ]));

        let got = serde_json::to_value(&path).expect("serialize");
        let expected = json!([
            42,
            [0, 116, 101, 114, 109],
            { "uuid": uuid.to_string() },
            { "fp": serde_json::to_value(fp).expect("fp to value") },
        ]);
        assert_eq!(got, expected);

        let roundtrip: StablePath = serde_json::from_value(got).expect("deserialize");
        assert_eq!(roundtrip, path);
    }

    #[test]
    fn serde_msgpack_bytes_roundtrip() {
        // `StableKey::Bytes` must survive a serde msgpack round-trip — it rides
        // inside component paths and target-state keys, which may embed raw
        // bytes. msgpack serializes a `Vec<u8>` as a native `bin`, so the
        // deserializer has to accept a `bin` (not just an int sequence).
        for key in [
            StableKey::Bytes(Arc::from(&b"\x00\x01\xff sha"[..])),
            // A nested array carrying a symbol, strings, and a raw-bytes key.
            StableKey::Array(Arc::from(vec![
                StableKey::Array(Arc::from(vec![
                    StableKey::Symbol(Arc::from("obj")),
                    StableKey::Str(Arc::from("tenant")),
                ])),
                StableKey::Str(Arc::from("src/main.rs")),
                StableKey::Bytes(Arc::from(&[0xde, 0xad, 0xbe, 0xef][..])),
            ])),
        ] {
            let bytes = rmp_serde::to_vec_named(&key).expect("encode");
            let decoded: StableKey = rmp_serde::from_slice(&bytes).expect("decode bytes key");
            assert_eq!(decoded, key);
        }
    }
}
