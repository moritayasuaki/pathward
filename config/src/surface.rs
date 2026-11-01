//! Iterative preflight for PathWard's deliberately small KDL 2 surface grammar.
//! This admits bounded, well-formed syntax before calling the upstream parser,
//! avoiding its recursive children, block comments, slashdash and error recovery.
//! It never decodes or rewrites values; kdl remains the authoritative decoder.
use crate::{
    ConfigError, MAX_HEADERS, MAX_PUBLICATIONS, MAX_REDIRECTS, MAX_ROUTE_RULES, MAX_SITES, error,
};

pub(crate) fn check(source: &str) -> Result<(), ConfigError> {
    let mut input = Surface { source, pos: 0 };
    input.layout();
    let mut sites = 0;
    while !input.eof() {
        sites += 1;
        if sites > MAX_SITES {
            return input.fail("expected at most 16 site blocks");
        }
        input.name("site")?;
        input.space()?;
        input.string()?;
        input.horizontal();
        input.literal(b'{', "expected site children block")?;
        input.layout();
        let mut directives = 0;
        while input.peek() != Some(b'}') {
            directives += 1;
            if directives
                > MAX_PUBLICATIONS + MAX_REDIRECTS + MAX_HEADERS + 4 * MAX_ROUTE_RULES + 34
            {
                return input.fail("too many site directives");
            }
            let start = input.pos;
            while input
                .peek()
                .is_some_and(|b| b.is_ascii_lowercase() || b == b'-')
            {
                input.pos += 1;
            }
            let arguments = match &source[start..input.pos] {
                "root"
                | "tls"
                | "reverse-proxy"
                | "deny"
                | "proxy-path"
                | "proxy-stream"
                | "websocket-origin"
                | "websocket-compression" => 1,
                "publish" | "proxy-limit" | "proxy-timeout" | "cache" | "cache-prefix"
                | "proxy-route" => 2,
                "redirect" | "redirect-prefix" => 4,
                "header" | "header-prefix" | "header-query" | "proxy-resource" => 3,
                _ => {
                    input.pos = start;
                    return input.fail("expected root, publish, or tls directive");
                }
            };
            for _ in 0..arguments {
                input.space()?;
                input.string()?;
            }
            input.end(false)?;
            input.layout();
        }
        input.pos += 1;
        input.end(true)?;
        input.layout();
    }
    Ok(())
}

struct Surface<'a> {
    source: &'a str,
    pos: usize,
}

impl Surface<'_> {
    fn eof(&self) -> bool {
        self.pos == self.source.len()
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.pos).copied()
    }

    fn fail<T>(&self, message: &str) -> Result<T, ConfigError> {
        Err(error(self.source, self.pos, message))
    }

    fn literal(&mut self, byte: u8, message: &str) -> Result<(), ConfigError> {
        if self.peek() != Some(byte) {
            return self.fail(message);
        }
        self.pos += 1;
        Ok(())
    }

    fn name(&mut self, name: &str) -> Result<(), ConfigError> {
        if !self.source[self.pos..].starts_with(name) {
            return self.fail("expected a site block");
        }
        self.pos += name.len();
        Ok(())
    }

    fn horizontal(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn space(&mut self) -> Result<(), ConfigError> {
        let start = self.pos;
        self.horizontal();
        if start == self.pos {
            return self.fail("expected a space before a quoted string");
        }
        Ok(())
    }

    fn newline(&mut self) -> bool {
        let rest = &self.source[self.pos..];
        // Match the complete KDL 2 newline set, with CRLF consumed together.
        for newline in [
            "\r\n", "\r", "\n", "\u{85}", "\u{b}", "\u{c}", "\u{2028}", "\u{2029}",
        ] {
            if rest.starts_with(newline) {
                self.pos += newline.len();
                return true;
            }
        }
        false
    }

    fn comment(&mut self) {
        if self.source[self.pos..].starts_with("//") {
            self.pos += 2;
            while !self.eof() {
                let start = self.pos;
                if self.newline() {
                    self.pos = start;
                    break;
                }
                self.pos += self.source[self.pos..].chars().next().unwrap().len_utf8();
            }
        }
    }

    fn layout(&mut self) {
        loop {
            self.horizontal();
            self.comment();
            if !self.newline() {
                break;
            }
        }
    }

    fn end(&mut self, allow_eof: bool) -> Result<(), ConfigError> {
        self.horizontal();
        self.comment();
        if self.newline() || (allow_eof && self.eof()) {
            return Ok(());
        }
        self.literal(b';', "expected newline or semicolon after node")
    }

    fn string(&mut self) -> Result<(), ConfigError> {
        self.literal(b'"', "expected an ordinary double-quoted string")?;
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't' | b's') => {
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            self.literal(b'{', "expected Unicode escape brace")?;
                            let start = self.pos;
                            while self.peek().is_some_and(|b| b.is_ascii_hexdigit()) {
                                self.pos += 1;
                                if self.pos - start > 6 {
                                    return self.fail("Unicode escape requires 1 to 6 hex digits");
                                }
                            }
                            let value = u32::from_str_radix(&self.source[start..self.pos], 16)
                                .ok()
                                .and_then(char::from_u32);
                            if value.is_none() {
                                return self.fail("invalid Unicode scalar escape");
                            }
                            self.literal(b'}', "expected Unicode escape closing brace")?;
                        }
                        _ => return self.fail("invalid or unsupported string escape"),
                    }
                }
                Some(0x20..=0x7e) => self.pos += 1,
                _ => return self.fail("strings require single-line ASCII literals or KDL escapes"),
            }
        }
    }
}
