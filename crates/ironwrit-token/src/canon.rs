//! Canonical forms for paths, URLs and email addresses.
//!
//! Policies compare strings, so every argument is reduced to one spelling
//! before it becomes a fact. Anything ambiguous is rejected rather than
//! guessed at: the caller turns an error into a denial.

use std::path::{Component, Path, PathBuf};

use percent_encoding::percent_decode_str;
use url::{Host, Url};

use crate::{Error, Result};

/// Messages never echo the input: they end up in the ledger, which must not
/// hold raw arguments (a URL can carry an API key).
fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidArgument(msg.into())
}

/// Resolve `input` (relative to `base`) to an absolute path with symlinks
/// resolved and `..` removed.
///
/// The result uses `/` separators. On Windows it is lowercased and the drive
/// letter is kept (`c:/docs/a.txt`), since paths there are case-insensitive.
/// Missing trailing components are allowed so new files can be authorized.
pub fn canonical_path(input: &str, base: &Path) -> Result<String> {
    if input.is_empty() {
        return Err(invalid("empty path"));
    }
    if input.contains('\0') {
        return Err(invalid("path contains NUL"));
    }
    // Servers disagree on whether `~` means the home directory.
    if input.starts_with('~') {
        return Err(invalid("paths starting with `~` are not supported"));
    }
    #[cfg(windows)]
    check_windows_syntax(input)?;

    let joined = base.join(input);
    // On Windows this applies the OS's own lexical rules (drive-relative
    // paths, trailing dots and spaces, `/` separators).
    let absolute = std::path::absolute(&joined)?;
    let lexical = normalize_lexically(&absolute);
    let resolved = resolve_symlinks(&lexical)?;

    // Lexical `..` and the kernel's `..` differ after a symlink: `link/..` is
    // the link's parent to Node's path.resolve but the target's parent to
    // open(2). If the two readings disagree, refuse to pick one. Windows
    // resolves `..` lexically, so there is only one reading there.
    #[cfg(not(windows))]
    if resolve_like_kernel(&absolute)? != resolved {
        return Err(invalid("ambiguous path (symlink followed by `..`)"));
    }
    to_canonical_string(&resolved)
}

/// Resolve `..` the way open(2) does: against the real directory, after
/// following any symlinks before it.
#[cfg(not(windows))]
fn resolve_like_kernel(path: &Path) -> Result<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if let Ok(real) = std::fs::canonicalize(&current) {
                    current = real;
                }
                current.pop();
            }
            other => current.push(other),
        }
    }
    resolve_symlinks(&current)
}

#[cfg(windows)]
fn check_windows_syntax(input: &str) -> Result<()> {
    let slashed = input.replace('\\', "/");
    if slashed.starts_with("//?/") || slashed.starts_with("//./") {
        return Err(invalid("device and verbatim paths are not supported"));
    }
    // A colon is only valid right after a drive letter; elsewhere it names an
    // alternate data stream.
    let after_drive = match input.as_bytes() {
        [letter, b':', ..] if letter.is_ascii_alphabetic() => &input[2..],
        _ => input,
    };
    if after_drive.contains(':') {
        return Err(invalid("alternate data streams are not supported"));
    }
    // Win32 strips trailing dots and spaces from the last component only, so
    // `docs /` names `docs ` but `docs ` alone names `docs`.
    let mut components: Vec<&str> = slashed.split('/').collect();
    components.pop();
    let ambiguous = components
        .iter()
        .any(|c| *c != "." && *c != ".." && (c.ends_with(' ') || c.ends_with('.')));
    if ambiguous {
        return Err(invalid(
            "path components ending in a space or dot are ambiguous on Windows",
        ));
    }
    Ok(())
}

/// Drop `.` and resolve `..` without touching the filesystem.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Canonicalize the longest existing prefix of `path`, then re-append the rest.
fn resolve_symlinks(path: &Path) -> Result<PathBuf> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(existing) {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Ok(resolved);
            }
            Err(_) => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Err(invalid("path has no existing ancestor"));
                };
                missing.push(name);
                existing = parent;
            }
        }
    }
}

fn to_canonical_string(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .ok_or_else(|| invalid("path is not valid UTF-8"))?;
    #[cfg(windows)]
    let s = {
        let s = if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{unc}")
        } else {
            s.strip_prefix(r"\\?\").unwrap_or(s).to_owned()
        };
        s.replace('\\', "/").to_lowercase()
    };
    let mut s = s.to_string();
    while s.len() > 1 && s.ends_with('/') && !s.ends_with(":/") {
        s.pop();
    }
    Ok(s)
}

/// The parts of a URL that policies match on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalUrl {
    /// Lowercase scheme, e.g. `https`.
    pub scheme: String,
    /// Lowercase ASCII host: IDNs become punycode, trailing dot removed.
    pub host: String,
    /// Explicit port, or the scheme's default.
    pub port: u16,
    /// Percent-decoded path with dot segments resolved.
    pub path: String,
}

/// Parse a URL the way browsers do (WHATWG), then reduce it to its parts.
pub fn canonical_url(input: &str) -> Result<CanonicalUrl> {
    let url = Url::parse(input.trim()).map_err(|e| invalid(format!("bad URL: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("URLs with credentials are not supported"));
    }
    let host = match url.host() {
        // One trailing dot is the fully qualified form of the same name; empty
        // labels (`a..b`, `x..`) aren't a real host and could re-parse as an IP.
        Some(Host::Domain(domain)) => {
            let domain = domain.strip_suffix('.').unwrap_or(domain);
            if domain.split('.').any(str::is_empty) {
                return Err(invalid("URL host has an empty label"));
            }
            domain.to_ascii_lowercase()
        }
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => ip.to_string(),
        None => return Err(invalid("URL has no host")),
    };
    if host.is_empty() {
        return Err(invalid("URL has no host"));
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid("URL has no port"))?;

    let path = percent_decode_str(url.path())
        .decode_utf8()
        .map_err(|_| invalid("URL path is not valid UTF-8"))?
        .into_owned();
    // Encoded dots and slashes survive URL parsing; once decoded they could
    // walk out of a prefix the policy allowed.
    let ambiguous = path.contains('\\')
        || path.contains('\0')
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..");
    if ambiguous {
        return Err(invalid("ambiguous URL path"));
    }
    Ok(CanonicalUrl {
        scheme: url.scheme().to_owned(),
        host,
        port,
        path,
    })
}

/// A recipient address, lowercased, with its domain in punycode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEmail {
    pub address: String,
    pub domain: String,
}

/// Accepts `user@example.com` or `Name <user@example.com>`. Lists such as
/// `a@x.com, b@y.com` are rejected: pass recipients as an array instead.
pub fn canonical_email(input: &str) -> Result<CanonicalEmail> {
    let trimmed = input.trim();
    let address = match (trimmed.rfind('<'), trimmed.strip_suffix('>')) {
        (Some(open), Some(inner)) => &inner[open + 1..],
        _ => trimmed,
    };
    let bad = || invalid("bad email address");
    if address
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || ",;<>\"()[]\\".contains(c))
    {
        return Err(bad());
    }
    let (local, domain) = address.split_once('@').ok_or_else(bad)?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(bad());
    }
    let domain = idna::domain_to_ascii(domain.trim_end_matches('.')).map_err(|_| bad())?;
    if domain.is_empty() {
        return Err(bad());
    }
    Ok(CanonicalEmail {
        address: format!("{}@{domain}", local.to_lowercase()),
        domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/a.txt"), "a").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "s").unwrap();
        let root = to_canonical_string(&std::fs::canonicalize(dir.path()).unwrap()).unwrap();
        (dir, root)
    }

    #[test]
    fn relative_and_absolute_agree() {
        let (dir, root) = base();
        let rel = canonical_path("docs/a.txt", dir.path()).unwrap();
        let abs = canonical_path(
            dir.path().join("docs/a.txt").to_str().unwrap(),
            Path::new("/"),
        )
        .unwrap();
        assert_eq!(rel, format!("{root}/docs/a.txt"));
        assert_eq!(rel, abs);
    }

    #[test]
    fn dot_dot_is_resolved() {
        let (dir, root) = base();
        let p = canonical_path("docs/../secret.txt", dir.path()).unwrap();
        assert_eq!(p, format!("{root}/secret.txt"));
        let p = canonical_path("docs/./missing/../../secret.txt", dir.path()).unwrap();
        assert_eq!(p, format!("{root}/secret.txt"));
    }

    #[test]
    fn missing_files_are_allowed() {
        let (dir, root) = base();
        let p = canonical_path("docs/new/file.txt", dir.path()).unwrap();
        assert_eq!(p, format!("{root}/docs/new/file.txt"));
    }

    #[test]
    fn trailing_slash_is_dropped() {
        let (dir, root) = base();
        assert_eq!(
            canonical_path("docs/", dir.path()).unwrap(),
            format!("{root}/docs")
        );
    }

    #[test]
    fn rejects_unsupported_syntax() {
        let (dir, _) = base();
        for p in ["", "~/x", "a\0b"] {
            assert!(
                canonical_path(p, dir.path()).is_err(),
                "{p:?} should be rejected"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_spellings_collapse() {
        let (dir, root) = base();
        for p in [
            r"DOCS\A.TXT",
            "docs/a.txt",
            r"docs\.\a.txt",
            "docs/a.txt.",
            "docs/a.txt  ",
        ] {
            assert_eq!(
                canonical_path(p, dir.path()).unwrap(),
                format!("{root}/docs/a.txt"),
                "{p:?}"
            );
        }
        assert!(root.starts_with(|c: char| c.is_ascii_lowercase()));
        assert!(!root.contains('\\'));
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_streams_and_devices() {
        let (dir, _) = base();
        for p in [
            r"docs\a.txt:secret",
            r"\\?\C:\docs\a.txt",
            r"\\.\pipe\x",
            "//?/c:/x",
            // Regressions found by tests/robustness.rs: not fixed points.
            "docs /a.txt",
            "docs./a.txt",
            "\u{130} /",
        ] {
            assert!(
                canonical_path(p, dir.path()).is_err(),
                "{p:?} should be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_resolved() {
        let (dir, root) = base();
        std::os::unix::fs::symlink(dir.path().join("secret.txt"), dir.path().join("docs/link"))
            .unwrap();
        assert_eq!(
            canonical_path("docs/link", dir.path()).unwrap(),
            format!("{root}/secret.txt")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_then_dot_dot_is_ambiguous() {
        let (dir, _) = base();
        std::fs::create_dir(dir.path().join("elsewhere")).unwrap();
        std::fs::create_dir(dir.path().join("elsewhere/sub")).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("elsewhere/sub"),
            dir.path().join("docs/sub"),
        )
        .unwrap();
        std::fs::write(dir.path().join("elsewhere/a.txt"), "x").unwrap();
        // Lexically docs/a.txt, but the kernel reads elsewhere/a.txt.
        assert!(canonical_path("docs/sub/../a.txt", dir.path()).is_err());
        // Same for a file that doesn't exist yet, so writes can't escape either.
        assert!(canonical_path("docs/sub/../new.txt", dir.path()).is_err());
    }

    #[test]
    fn urls_are_canonical() {
        let u = canonical_url("HTTPS://News.Example.TEST./a/./b/../c?q=1#f").unwrap();
        assert_eq!(
            u,
            CanonicalUrl {
                scheme: "https".into(),
                host: "news.example.test".into(),
                port: 443,
                path: "/a/c".into(),
            }
        );
        assert_eq!(
            canonical_url("http://example.test:8080/").unwrap().port,
            8080
        );
        assert_eq!(canonical_url("http://[::1]/").unwrap().host, "::1");
    }

    #[test]
    fn idn_hosts_become_punycode() {
        assert_eq!(
            canonical_url("https://bücher.example/").unwrap().host,
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn userinfo_does_not_hide_the_host() {
        assert!(canonical_url("https://news.example.test@evil.test/").is_err());
    }

    #[test]
    fn encoded_traversal_is_rejected() {
        for u in [
            "https://example.test/public/..%2fsecret",
            "https://example.test/public/..%5csecret",
            "https://example.test/public/%2e%2e%2fsecret",
        ] {
            assert!(canonical_url(u).is_err(), "{u} should be rejected");
        }
        // Encoded dot segments are resolved by the parser, like servers do.
        assert_eq!(
            canonical_url("https://example.test/public/%2e%2e/secret")
                .unwrap()
                .path,
            "/secret"
        );
        assert_eq!(
            canonical_url("https://example.test/a%20b").unwrap().path,
            "/a b"
        );
    }

    #[test]
    fn urls_without_hosts_are_rejected() {
        // `https://0..` is a regression found by tests/robustness.rs.
        for u in [
            "mailto:a@b.test",
            "file:///etc/passwd",
            "not a url",
            "https://0..",
            "https://a..b/",
        ] {
            assert!(canonical_url(u).is_err(), "{u} should be rejected");
        }
    }

    #[test]
    fn emails_are_canonical() {
        let e = canonical_email(" Bob <Bob@Example.TEST> ").unwrap();
        assert_eq!(e.address, "bob@example.test");
        assert_eq!(e.domain, "example.test");
        assert_eq!(
            canonical_email("x@bücher.example").unwrap().domain,
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn bad_emails_are_rejected() {
        for e in [
            "",
            "nobody",
            "@x.test",
            "a@",
            "a@b@c",
            "a@x.test, b@y.test",
            "a b@x.test",
        ] {
            assert!(canonical_email(e).is_err(), "{e:?} should be rejected");
        }
    }
}
