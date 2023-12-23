// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::net::IpAddr;
use std::str::FromStr;

/// A `DNSName` is an `asn1::IA5String` with additional invariant preservations
/// per [RFC 5280 4.2.1.6], which in turn uses the preferred name syntax defined
/// in [RFC 1034 3.5] and amended in [RFC 1123 2.1].
///
/// Non-ASCII domain names (i.e., internationalized names) must be pre-encoded;
/// comparisons are case-insensitive.
///
/// [RFC 5280 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
/// [RFC 1034 3.5]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.5
/// [RFC 1123 2.1]: https://datatracker.ietf.org/doc/html/rfc1123#section-2.1
///
/// ```rust
/// # use cryptography_x509_verification::types::DNSName;
/// assert_eq!(DNSName::new("foo.com").unwrap(), DNSName::new("FOO.com").unwrap());
/// ```
#[derive(Clone, Debug)]
pub struct DNSName<'a>(asn1::IA5String<'a>);

impl<'a> DNSName<'a> {
    pub fn new(value: &'a str) -> Option<Self> {
        // Domains cannot be empty and must (practically)
        // be less than 253 characters (255 in RFC 1034's octet encoding).
        if value.is_empty() || value.len() > 253 {
            None
        } else {
            for label in value.split('.') {
                // Individual labels cannot be empty; cannot exceed 63 characters;
                // cannot start or end with `-`.
                // NOTE: RFC 1034's grammar prohibits consecutive hyphens, but these
                // are used as part of the IDN prefix (e.g. `xn--`)'; we allow them here.
                if label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                {
                    return None;
                }

                // Labels must only contain `a-zA-Z0-9-`.
                if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return None;
                }
            }
            asn1::IA5String::new(value).map(Self)
        }
    }

    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }

    /// Return this `DNSName`'s parent domain, if it has one.
    ///
    /// ```rust
    /// # use cryptography_x509_verification::types::DNSName;
    /// let domain = DNSName::new("foo.example.com").unwrap();
    /// assert_eq!(domain.parent().unwrap().as_str(), "example.com");
    /// ```
    pub fn parent(&self) -> Option<Self> {
        match self.as_str().split_once('.') {
            Some((_, parent)) => Self::new(parent),
            None => None,
        }
    }

    /// Returns this DNS name's labels, in reversed order
    /// (from top-level domain to most-specific subdomain).
    fn rlabels(&self) -> impl Iterator<Item = &'_ str> {
        self.as_str().rsplit('.')
    }
}

impl PartialEq for DNSName<'_> {
    fn eq(&self, other: &Self) -> bool {
        // DNS names are always case-insensitive.
        self.as_str().eq_ignore_ascii_case(other.as_str())
    }
}

/// A `DNSPattern` represents a subset of the domain name wildcard matching
/// behavior defined in [RFC 6125 6.4.3]. In particular, all DNS patterns
/// must either be exact matches (post-normalization) *or* a single wildcard
/// matching a full label in the left-most label position. Partial label matching
/// (e.g. `f*o.example.com`) is not supported, nor is non-left-most matching
/// (e.g. `foo.*.example.com`).
///
/// [RFC 6125 6.4.3]: https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3
#[derive(Debug, PartialEq)]
pub enum DNSPattern<'a> {
    Exact(DNSName<'a>),
    Wildcard(DNSName<'a>),
}

impl<'a> DNSPattern<'a> {
    pub fn new(pat: &'a str) -> Option<Self> {
        if let Some(pat) = pat.strip_prefix("*.") {
            DNSName::new(pat).map(Self::Wildcard)
        } else {
            DNSName::new(pat).map(Self::Exact)
        }
    }

    pub fn matches(&self, name: &DNSName<'_>) -> bool {
        match self {
            Self::Exact(pat) => pat == name,
            Self::Wildcard(pat) => match name.parent() {
                Some(ref parent) => pat == parent,
                // No parent means we have a single label; wildcards cannot match single labels.
                None => false,
            },
        }
    }
}

/// A `DNSConstraint` represents a DNS name constraint as defined in [RFC 5280 4.2.1.10].
///
/// [RFC 5280 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
pub struct DNSConstraint<'a>(DNSName<'a>);

impl<'a> DNSConstraint<'a> {
    pub fn new(pattern: &'a str) -> Option<Self> {
        DNSName::new(pattern).map(Self)
    }

    /// Returns true if this `DNSConstraint` matches the given name.
    ///
    /// Constraint matching is defined by RFC 5280: any DNS name that can
    /// be constructed by simply adding zero or more labels to the left-hand
    /// side of the name satisfies the name constraint.
    ///
    /// ```rust
    /// # use cryptography_x509_verification::types::{DNSConstraint, DNSName};
    /// let example_com = DNSName::new("example.com").unwrap();
    /// let badexample_com = DNSName::new("badexample.com").unwrap();
    /// let foo_example_com = DNSName::new("foo.example.com").unwrap();
    /// assert!(DNSConstraint::new(example_com.as_str()).unwrap().matches(&example_com));
    /// assert!(DNSConstraint::new(example_com.as_str()).unwrap().matches(&foo_example_com));
    /// assert!(!DNSConstraint::new(example_com.as_str()).unwrap().matches(&badexample_com));
    /// ```
    pub fn matches(&self, name: &DNSName<'_>) -> bool {
        // NOTE: This may seem like an obtuse way to perform label matching,
        // but it saves us a few allocations: doing a substring check instead
        // would require us to clone each string and do case normalization.
        // Note also that we check the length in advance: Rust's zip
        // implementation terminates with the shorter iterator, so we need
        // to first check that the candidate name is at least as long as
        // the constraint it's matching against.
        name.as_str().len() >= self.0.as_str().len()
            && self
                .0
                .rlabels()
                .zip(name.rlabels())
                .all(|(a, o)| a.eq_ignore_ascii_case(o))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IPAddress(IpAddr);

/// An `IPAddress` represents an IP address as defined in [RFC 5280 4.2.1.6].
///
/// [RFC 5280 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
impl IPAddress {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        IpAddr::from_str(s).ok().map(Self::from)
    }

    /// Constructs an `IPAddress` from a slice. The provided data must be
    /// 4 (IPv4) or 16 (IPv6) bytes in "network byte order", as specified by
    /// [RFC 5280].
    ///
    /// [RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b.len() {
            4 => {
                let b: [u8; 4] = b.try_into().ok()?;
                Some(IpAddr::from(b).into())
            }
            16 => {
                let b: [u8; 16] = b.try_into().ok()?;
                Some(IpAddr::from(b).into())
            }
            _ => None,
        }
    }

    /// Parses the octets of the `IPAddress` as a mask. If it is well-formed,
    /// i.e., has only one contiguous block of set bits starting from the most
    /// significant bit, a prefix is returned.
    pub fn as_prefix(&self) -> Option<u8> {
        let (leading, total) = match self.0 {
            IpAddr::V4(a) => {
                let data = u32::from_be_bytes(a.octets());
                (data.leading_ones(), data.count_ones())
            }
            IpAddr::V6(a) => {
                let data = u128::from_be_bytes(a.octets());
                (data.leading_ones(), data.count_ones())
            }
        };

        if leading != total {
            None
        } else {
            Some(leading as u8)
        }
    }

    /// Returns a new `IPAddress` with the first `prefix` bits of the `IPAddress`.
    ///
    /// ```rust
    /// # use cryptography_x509_verification::types::IPAddress;
    /// let ip = IPAddress::from_str("192.0.2.1").unwrap();
    /// assert_eq!(ip.mask(24), IPAddress::from_str("192.0.2.0").unwrap());
    /// ```
    pub fn mask(&self, prefix: u8) -> Self {
        match self.0 {
            IpAddr::V4(a) => {
                let prefix = 32u8.saturating_sub(prefix).into();
                let masked = u32::from_be_bytes(a.octets())
                    & u32::MAX
                        .checked_shr(prefix)
                        .unwrap_or(0)
                        .checked_shl(prefix)
                        .unwrap_or(0);
                Self::from_bytes(&masked.to_be_bytes()).unwrap()
            }
            IpAddr::V6(a) => {
                let prefix = 128u8.saturating_sub(prefix).into();
                let masked = u128::from_be_bytes(a.octets())
                    & u128::MAX
                        .checked_shr(prefix)
                        .unwrap_or(0)
                        .checked_shl(prefix)
                        .unwrap_or(0);
                Self::from_bytes(&masked.to_be_bytes()).unwrap()
            }
        }
    }
}

impl From<IpAddr> for IPAddress {
    fn from(addr: IpAddr) -> Self {
        Self(addr)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct IPConstraint {
    address: IPAddress,
    prefix: u8,
}

/// An `IPConstraint` represents a CIDR-style IP address range used in a name constraints
/// extension, as defined by [RFC 5280 4.2.1.10].
///
/// [RFC 5280 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
impl IPConstraint {
    /// Constructs an `IPConstraint` from a slice. The input slice must be 8 (IPv4)
    /// or 32 (IPv6) bytes long and contain two IP addresses, the first being
    /// a subnet and the second defining the subnet's mask.
    ///
    /// The subnet mask must contain only one contiguous run of set bits starting
    /// from the most significant bit. For example, a valid IPv4 subnet mask would
    /// be FF FF 00 00, whereas an invalid IPv4 subnet mask would be FF EF 00 00.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let slice_idx = match b.len() {
            8 => 4,
            32 => 16,
            _ => return None,
        };

        let prefix = IPAddress::from_bytes(&b[slice_idx..])?.as_prefix()?;
        Some(IPConstraint {
            address: IPAddress::from_bytes(&b[..slice_idx])?.mask(prefix),
            prefix,
        })
    }

    /// Determines if the `addr` is within the `IPConstraint`.
    ///
    /// ```rust
    /// # use cryptography_x509_verification::types::{IPAddress, IPConstraint};
    /// let range_bytes = b"\xc6\x33\x64\x00\xff\xff\xff\x00";
    /// let range = IPConstraint::from_bytes(range_bytes).unwrap();
    /// assert!(range.matches(&IPAddress::from_str("198.51.100.42").unwrap()));
    /// ```
    pub fn matches(&self, addr: &IPAddress) -> bool {
        self.address == addr.mask(self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{DNSConstraint, DNSName, DNSPattern, IPAddress, IPConstraint};

    #[test]
    fn test_dnsname_debug_trait() {
        // Just to get coverage on the `Debug` derive.
        assert_eq!(
            "DNSName(IA5String(\"example.com\"))",
            format!("{:?}", DNSName::new("example.com").unwrap())
        );
    }

    #[test]
    fn test_dnsname_new() {
        assert_eq!(DNSName::new(""), None);
        assert_eq!(DNSName::new("."), None);
        assert_eq!(DNSName::new(".."), None);
        assert_eq!(DNSName::new(".a."), None);
        assert_eq!(DNSName::new("a.a."), None);
        assert_eq!(DNSName::new(".a"), None);
        assert_eq!(DNSName::new("a."), None);
        assert_eq!(DNSName::new("a.."), None);
        assert_eq!(DNSName::new(" "), None);
        assert_eq!(DNSName::new("\t"), None);
        assert_eq!(DNSName::new(" whitespace "), None);
        assert_eq!(DNSName::new("white. space"), None);
        assert_eq!(DNSName::new("!badlabel!"), None);
        assert_eq!(DNSName::new("bad!label"), None);
        assert_eq!(DNSName::new("goodlabel.!badlabel!"), None);
        assert_eq!(DNSName::new("-foo.bar.example.com"), None);
        assert_eq!(DNSName::new("foo-.bar.example.com"), None);
        assert_eq!(DNSName::new("foo.-bar.example.com"), None);
        assert_eq!(DNSName::new("foo.bar-.example.com"), None);
        assert_eq!(DNSName::new(&"a".repeat(64)), None);
        assert_eq!(DNSName::new("⚠️"), None);
        assert_eq!(DNSName::new(".foo.example"), None);
        assert_eq!(DNSName::new(".example.com"), None);

        let long_valid_label = "a".repeat(63);
        let long_name = std::iter::repeat(long_valid_label)
            .take(5)
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(DNSName::new(&long_name), None);

        assert_eq!(
            DNSName::new(&"a".repeat(63)).unwrap().as_str(),
            "a".repeat(63)
        );
        assert_eq!(DNSName::new("example.com").unwrap().as_str(), "example.com");
        assert_eq!(
            DNSName::new("123.example.com").unwrap().as_str(),
            "123.example.com"
        );
        assert_eq!(DNSName::new("EXAMPLE.com").unwrap().as_str(), "EXAMPLE.com");
        assert_eq!(DNSName::new("EXAMPLE.COM").unwrap().as_str(), "EXAMPLE.COM");
        assert_eq!(
            DNSName::new("xn--bcher-kva.example").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn test_dnsname_equality() {
        assert_ne!(
            DNSName::new("foo.example.com").unwrap(),
            DNSName::new("example.com").unwrap()
        );

        // DNS name comparisons are case insensitive.
        assert_eq!(
            DNSName::new("EXAMPLE.COM").unwrap(),
            DNSName::new("example.com").unwrap()
        );
        assert_eq!(
            DNSName::new("ExAmPLe.CoM").unwrap(),
            DNSName::new("eXaMplE.cOm").unwrap()
        );
    }

    #[test]
    fn test_dnsname_parent() {
        assert_eq!(DNSName::new("localhost").unwrap().parent(), None);
        assert_eq!(
            DNSName::new("example.com").unwrap().parent().unwrap(),
            DNSName::new("com").unwrap()
        );
        assert_eq!(
            DNSName::new("foo.example.com").unwrap().parent().unwrap(),
            DNSName::new("example.com").unwrap()
        );
    }

    #[test]
    fn test_dnspattern_new() {
        assert_eq!(DNSPattern::new("*"), None);
        assert_eq!(DNSPattern::new("*."), None);
        assert_eq!(DNSPattern::new("f*o.example.com"), None);
        assert_eq!(DNSPattern::new("*oo.example.com"), None);
        assert_eq!(DNSPattern::new("fo*.example.com"), None);
        assert_eq!(DNSPattern::new("foo.*.example.com"), None);
        assert_eq!(DNSPattern::new("*.foo.*.example.com"), None);

        assert_eq!(
            DNSPattern::new("example.com").unwrap(),
            DNSPattern::Exact(DNSName::new("example.com").unwrap())
        );
        assert_eq!(
            DNSPattern::new("*.example.com").unwrap(),
            DNSPattern::Wildcard(DNSName::new("example.com").unwrap())
        );
    }

    #[test]
    fn test_dnspattern_matches() {
        let exactly_localhost = DNSPattern::new("localhost").unwrap();
        let any_localhost = DNSPattern::new("*.localhost").unwrap();
        let exactly_example_com = DNSPattern::new("example.com").unwrap();
        let any_example_com = DNSPattern::new("*.example.com").unwrap();

        // Exact patterns match only the exact name.
        assert!(exactly_localhost.matches(&DNSName::new("localhost").unwrap()));
        assert!(exactly_localhost.matches(&DNSName::new("LOCALHOST").unwrap()));
        assert!(exactly_example_com.matches(&DNSName::new("example.com").unwrap()));
        assert!(exactly_example_com.matches(&DNSName::new("EXAMPLE.com").unwrap()));
        assert!(!exactly_example_com.matches(&DNSName::new("foo.example.com").unwrap()));

        // Wildcard patterns match any subdomain, but not the parent or nested subdomains.
        assert!(any_example_com.matches(&DNSName::new("foo.example.com").unwrap()));
        assert!(any_example_com.matches(&DNSName::new("bar.example.com").unwrap()));
        assert!(any_example_com.matches(&DNSName::new("BAZ.example.com").unwrap()));
        assert!(!any_example_com.matches(&DNSName::new("example.com").unwrap()));
        assert!(!any_example_com.matches(&DNSName::new("foo.bar.example.com").unwrap()));
        assert!(!any_example_com.matches(&DNSName::new("foo.bar.baz.example.com").unwrap()));
        assert!(!any_localhost.matches(&DNSName::new("localhost").unwrap()));
    }

    #[test]
    fn test_dnsconstraint_new() {
        assert!(DNSConstraint::new("").is_none());
        assert!(DNSConstraint::new(".").is_none());
        assert!(DNSConstraint::new("*.").is_none());
        assert!(DNSConstraint::new("*").is_none());
        assert!(DNSConstraint::new(".example").is_none());
        assert!(DNSConstraint::new("*.example").is_none());
        assert!(DNSConstraint::new("*.example.com").is_none());

        assert!(DNSConstraint::new("example").is_some());
        assert!(DNSConstraint::new("example.com").is_some());
        assert!(DNSConstraint::new("foo.example.com").is_some());
    }

    #[test]
    fn test_dnsconstraint_matches() {
        let example_com = DNSConstraint::new("example.com").unwrap();

        // Exact domain and arbitrary subdomains match.
        assert!(example_com.matches(&DNSName::new("example.com").unwrap()));
        assert!(example_com.matches(&DNSName::new("foo.example.com").unwrap()));
        assert!(example_com.matches(&DNSName::new("foo.bar.baz.quux.example.com").unwrap()));

        // Parent domains, distinct domains, and substring domains do not match.
        assert!(!example_com.matches(&DNSName::new("com").unwrap()));
        assert!(!example_com.matches(&DNSName::new("badexample.com").unwrap()));
        assert!(!example_com.matches(&DNSName::new("wrong.com").unwrap()));
    }

    #[test]
    fn test_ipaddress_from_str() {
        assert_ne!(IPAddress::from_str("192.168.1.1"), None)
    }

    #[test]
    fn test_ipaddress_from_bytes() {
        let ipv4 = b"\xc0\x00\x02\x01";
        let ipv6 = b"\x20\x01\x0d\xb8\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x01";
        let bad = b"\xde\xad";

        assert_eq!(
            IPAddress::from_bytes(ipv4).unwrap(),
            IPAddress::from_str("192.0.2.1").unwrap(),
        );
        assert_eq!(
            IPAddress::from_bytes(ipv6).unwrap(),
            IPAddress::from_str("2001:db8::1").unwrap(),
        );
        assert_eq!(IPAddress::from_bytes(bad), None);
    }

    #[test]
    fn test_ipaddress_as_prefix() {
        let ipv4 = IPAddress::from_str("255.255.255.0").unwrap();
        let ipv6 = IPAddress::from_str("ffff:ffff:ffff:ffff::").unwrap();
        let ipv4_nonmask = IPAddress::from_str("192.0.2.1").unwrap();
        let ipv6_nonmask = IPAddress::from_str("2001:db8::1").unwrap();

        assert_eq!(ipv4.as_prefix(), Some(24));
        assert_eq!(ipv6.as_prefix(), Some(64));
        assert_eq!(ipv4_nonmask.as_prefix(), None);
        assert_eq!(ipv6_nonmask.as_prefix(), None);
    }

    #[test]
    fn test_ipaddress_mask() {
        let ipv4 = IPAddress::from_str("192.0.2.252").unwrap();
        let ipv6 = IPAddress::from_str("2001:db8::f00:01ba").unwrap();

        assert_eq!(ipv4.mask(0), IPAddress::from_str("0.0.0.0").unwrap());
        assert_eq!(ipv4.mask(64), ipv4);
        assert_eq!(ipv4.mask(32), ipv4);
        assert_eq!(ipv4.mask(24), IPAddress::from_str("192.0.2.0").unwrap());
        assert_eq!(ipv6.mask(0), IPAddress::from_str("::0").unwrap());
        assert_eq!(ipv6.mask(130), ipv6);
        assert_eq!(ipv6.mask(128), ipv6);
        assert_eq!(ipv6.mask(64), IPAddress::from_str("2001:db8::").unwrap());
        assert_eq!(
            ipv6.mask(103),
            IPAddress::from_str("2001:db8::e00:0").unwrap()
        );
    }

    #[test]
    fn test_ipconstraint_from_bytes() {
        let ipv4_bad = b"\xc0\xa8\x01\x01\xff\xfe\xff\x00";
        let ipv4_bad_many_bits = b"\xc0\xa8\x01\x01\xff\xfc\xff\x00";
        let ipv4_bad_octet = b"\xc0\xa8\x01\x01\x00\xff\xff\xff";
        let ipv6_bad = b"\
            \x26\x01\x00\x00\x00\x00\x00\x01\
            \x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x01\
            \x00\x00\x00\x00\x00\x00\x00\x00";
        let ipv6_good = b"\
            \x20\x01\x0d\xb8\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x01\
            \xf0\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00";
        let bad = b"\xff\xff\xff";

        assert_eq!(IPConstraint::from_bytes(ipv4_bad), None);
        assert_eq!(IPConstraint::from_bytes(ipv4_bad_many_bits), None);
        assert_eq!(IPConstraint::from_bytes(ipv4_bad_octet), None);
        assert_eq!(IPConstraint::from_bytes(ipv6_bad), None);
        assert_ne!(IPConstraint::from_bytes(ipv6_good), None);
        assert_eq!(IPConstraint::from_bytes(bad), None);

        // 192.168.1.1/16
        let ipv4_with_extra = b"\xc0\xa8\x01\x01\xff\xff\x00\x00";
        assert_ne!(IPConstraint::from_bytes(ipv4_with_extra), None);

        // 192.168.0.0/16
        let ipv4_masked = b"\xc0\xa8\x00\x00\xff\xff\x00\x00";
        assert_eq!(
            IPConstraint::from_bytes(ipv4_with_extra),
            IPConstraint::from_bytes(ipv4_masked)
        );
    }

    #[test]
    fn test_ipconstraint_matches() {
        // 192.168.1.1/16
        let ipv4 = IPConstraint::from_bytes(b"\xc0\xa8\x01\x01\xff\xff\x00\x00").unwrap();
        let ipv4_32 = IPConstraint::from_bytes(b"\xc0\x00\x02\xde\xff\xff\xff\xff").unwrap();
        let ipv6 = IPConstraint::from_bytes(
            b"\x26\x00\x0d\xb8\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x01\
              \xff\xff\xff\xff\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00",
        )
        .unwrap();
        let ipv6_128 = IPConstraint::from_bytes(
            b"\x26\x00\x0d\xb8\x00\x00\x00\x00\
              \x00\x00\x00\x00\xff\x00\xde\xde\
              \xff\xff\xff\xff\xff\xff\xff\xff\
              \xff\xff\xff\xff\xff\xff\xff\xff",
        )
        .unwrap();

        assert!(ipv4.matches(&IPAddress::from_str("192.168.0.50").unwrap()));
        assert!(!ipv4.matches(&IPAddress::from_str("192.160.0.50").unwrap()));
        assert!(ipv4_32.matches(&IPAddress::from_str("192.0.2.222").unwrap()));
        assert!(!ipv4_32.matches(&IPAddress::from_str("192.5.2.222").unwrap()));
        assert!(!ipv4_32.matches(&IPAddress::from_str("192.0.2.1").unwrap()));
        assert!(ipv6.matches(&IPAddress::from_str("2600:db8::abba").unwrap()));
        assert!(ipv6_128.matches(&IPAddress::from_str("2600:db8::ff00:dede").unwrap()));
        assert!(!ipv6_128.matches(&IPAddress::from_str("2600::ff00:dede").unwrap()));
        assert!(!ipv6_128.matches(&IPAddress::from_str("2600:db8::ff00:0").unwrap()));
    }
}
