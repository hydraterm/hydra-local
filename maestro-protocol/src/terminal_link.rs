//! Shared, allocation-free policy for terminal-output links.
//!
//! Terminal text is untrusted.  Both the daemon (before adding OSC 8 metadata to the
//! cell wire) and the renderer (immediately before hit-testing/native opening) apply
//! this same closed validator so the two mirrors cannot drift.

/// Maximum UTF-8 byte length of one terminal URL retained on the local wire.
pub const MAX_TERMINAL_URL_BYTES: usize = 2_048;

/// Maximum OSC 8-linked cells retained in one snapshot/scrollback frame.  Plain-text
/// detection has its own renderer-local span cap and never expands the wire.
pub const MAX_TERMINAL_LINK_CELLS_PER_FRAME: usize = 256;

/// Return `true` only for one bounded, absolute HTTP(S) URL that is safe to pass as a
/// single argument to the fixed native opener.
///
/// This is deliberately stricter than a browser parser: it rejects whitespace,
/// controls, backslashes, malformed percent escapes, missing hosts, and ambiguous
/// ports instead of allowing a platform opener to repair or reinterpret them.
pub fn is_safe_terminal_http_url(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_TERMINAL_URL_BYTES {
        return false;
    }
    if value
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '\\' | '"'))
    {
        return false;
    }

    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let scheme = &value[..scheme_end];
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    let remainder = &value[scheme_end + 3..];
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() {
        return false;
    }

    // Keep the first policy deliberately narrower than the full URL grammar:
    // credentials/userinfo are not needed for terminal navigation and make the
    // visible authority ambiguous. IDNs remain available in their ASCII punycode
    // form.
    if authority.contains('@') {
        return false;
    }
    let host_port = authority;
    let host_ok = if let Some(bracketed) = host_port.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return false;
        };
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        host.parse::<std::net::Ipv6Addr>().is_ok() && valid_port_suffix(suffix)
    } else {
        // An unbracketed authority may contain at most one colon (the port
        // separator); IPv6 literals must use brackets.
        let colon_count = host_port.bytes().filter(|byte| *byte == b':').count();
        if colon_count > 1 {
            false
        } else {
            let (host, suffix) = match host_port.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_port, None),
            };
            valid_ascii_host(host) && suffix.is_none_or(valid_port)
        }
    };
    if !host_ok {
        return false;
    }

    // A stray '%' is interpreted inconsistently by native URL handlers.  Require
    // every occurrence to be one complete byte escape.
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port)
}

fn valid_ascii_host(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .next_back()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_bounded_absolute_http_urls() {
        for accepted in [
            "http://example.com",
            "HTTPS://example.com:443/a?q=one#two",
            "https://localhost/path",
            "https://[2001:db8::1]:8443/a",
            "https://xn--bcher-kva.example/a%20b",
        ] {
            assert!(is_safe_terminal_http_url(accepted), "{accepted}");
        }

        for refused in [
            "file:///tmp/x",
            "javascript:alert(1)",
            "data:text/plain,x",
            "shell://echo",
            "https:/example.com",
            "https://",
            "https://?query",
            "https://user@",
            "https://user:pass@example.com/secret",
            "https://example.com:bad/",
            "https://example.com:70000/",
            "https://2001:db8::1/",
            "https://[bad]/",
            "https://bad..example/",
            "https://-bad.example/",
            "https://example.com/a b",
            "https://example.com\\evil",
            "https://example.com/\"ambiguous",
            "https://example.com/%zz",
            "https://example.com/\nnext",
        ] {
            assert!(!is_safe_terminal_http_url(refused), "{refused}");
        }

        let overlong = format!("https://example.com/{}", "x".repeat(MAX_TERMINAL_URL_BYTES));
        assert!(!is_safe_terminal_http_url(&overlong));
    }
}
