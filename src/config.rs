// Copyright © 2024-26 The Johns Hopkins Applied Physics Laboratory LLC.
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License,
// version 3, as published by the Free Software Foundation.  If you
// would like to purchase a commercial license for this software, please
// contact APL’s Tech Transfer at 240-592-0817 or
// techtransfer@jhuapl.edu.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use constellation_common::net::IPEndpointAddr;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "test-cred")]
#[serde(untagged)]
pub enum TestCredConfig {
    IP { ip: UnsafeBasicCredConfig },
    Unix { unix: PathBuf }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "test-authn-config")]
#[serde(rename_all = "kebab-case")]
pub struct TestAuthNPrinConfig<Prin, Cred> {
    prin: Prin,
    cred: Vec<Cred>
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "basic-cred")]
#[serde(untagged)]
pub enum BasicCredConfig {
    Unsafe {
        #[serde(rename = "unsafe")]
        unsafe_cred: UnsafeBasicCredConfig
    },
    Unix {
        unix: PathBuf
    },
    SSL {
        ssl: BasicSSLCredConfig
    },
    #[cfg(feature = "gssapi")]
    GSSAPI {
        gssapi: BasicGSSAPICredConfig
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "unsafe-basic-ip-matcher")]
#[serde(rename_all = "kebab-case")]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display {
    port: Option<u16>,
    addr: Addr
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "unsafe-basic-cred")]
#[serde(untagged)]
pub enum UnsafeBasicCredConfig {
    IP {
        #[serde(rename = "ip")]
        unsafe_ip: BasicIPMatcherConfig<IpAddr>
    },
    SOCKS5 {
        #[serde(rename = "socks5")]
        unsafe_ip: BasicIPMatcherConfig<IPEndpointAddr>
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "basic-ssl-cred")]
#[serde(rename_all = "kebab-case")]
pub struct BasicSSLCredConfig {
    subject_name: Vec<String>,
    #[serde(flatten)]
    #[serde(default)]
    inner: Option<Box<BasicCredConfig>>
}

#[cfg(feature = "gssapi")]
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-ssl-cred")]
#[serde(rename_all = "kebab-case")]
pub struct BasicGSSAPICredConfig {
    name: String
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-authn-config")]
#[serde(rename_all = "kebab-case")]
pub struct BasicAuthNPrinConfig<Prin, Cred> {
    prin: Prin,
    cred: Cred
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct HostAuthNUnsafeConfig {
    allow_ip_addr_creds: bool
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "basic-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct BasicAuthNConfig<Prin> {
    rules: Vec<BasicAuthNPrinConfig<Prin, BasicCredConfig>>,
    #[serde(default)]
    #[serde(rename = "unsafe")]
    unsafe_opts: HostAuthNUnsafeConfig
}

pub type TestAuthNConfig<Prin, Cred> = Vec<TestAuthNPrinConfig<Prin, Cred>>;

#[derive(Debug)]
pub enum BadIPMatcher<Addr> {
    Addr { err: Addr },
    BadFormat { err: String }
}

impl<Addr> BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display
{
    #[inline]
    pub fn take(self) -> (Addr, Option<u16>) {
        (self.addr, self.port)
    }
}

impl<Addr> From<BasicIPMatcherConfig<Addr>> for String
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display
{
    fn from(val: BasicIPMatcherConfig<Addr>) -> String {
        format!("{}", val)
    }
}

impl<Addr> TryFrom<&'_ str> for BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display
{
    type Error = BadIPMatcher<Addr::Err>;

    #[inline]
    fn try_from(str: &str) -> Result<Self, BadIPMatcher<Addr::Err>> {
        str.parse()
    }
}

impl<Addr> TryFrom<String> for BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display
{
    type Error = BadIPMatcher<Addr::Err>;

    #[inline]
    fn try_from(str: String) -> Result<Self, BadIPMatcher<Addr::Err>> {
        str.parse()
    }
}

impl<Addr> FromStr for BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display
{
    type Err = BadIPMatcher<Addr::Err>;

    fn from_str(str: &str) -> Result<Self, BadIPMatcher<Addr::Err>> {
        match str.strip_suffix(":*") {
            Some(val) => {
                let val = match val.strip_prefix('[') {
                    Some(val) => val.strip_suffix(']').ok_or(
                        BadIPMatcher::BadFormat {
                            err: str.to_string()
                        }
                    )?,
                    None => val
                };
                let addr = val
                    .parse()
                    .map_err(|err| BadIPMatcher::Addr { err: err })?;

                Ok(BasicIPMatcherConfig {
                    port: None,
                    addr: addr
                })
            }
            None => {
                let (addr, port) = match str.strip_prefix('[') {
                    Some(val) => {
                        val.split_once("]:").ok_or(BadIPMatcher::BadFormat {
                            err: str.to_string()
                        })?
                    }
                    None => {
                        str.rsplit_once(':').ok_or(BadIPMatcher::BadFormat {
                            err: str.to_string()
                        })?
                    }
                };
                let addr = addr
                    .parse()
                    .map_err(|err| BadIPMatcher::Addr { err: err })?;
                let port =
                    port.parse().map_err(|_| BadIPMatcher::BadFormat {
                        err: str.to_string()
                    })?;

                Ok(BasicIPMatcherConfig {
                    port: Some(port),
                    addr: addr
                })
            }
        }
    }
}

impl Default for HostAuthNUnsafeConfig {
    #[inline]
    fn default() -> Self {
        HostAuthNUnsafeConfig {
            allow_ip_addr_creds: false
        }
    }
}

impl BasicGSSAPICredConfig {
    #[inline]
    pub fn new(name: String) -> Self {
        BasicGSSAPICredConfig { name: name }
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn take(self) -> String {
        self.name
    }
}

impl BasicSSLCredConfig {
    #[inline]
    pub fn new(
        subject_name: Vec<String>,
        inner: Option<Box<BasicCredConfig>>
    ) -> Self {
        BasicSSLCredConfig {
            subject_name: subject_name,
            inner: inner
        }
    }

    #[inline]
    pub fn subject_name(&self) -> &[String] {
        &self.subject_name
    }

    #[inline]
    pub fn inner(&self) -> Option<&BasicCredConfig> {
        self.inner.as_deref()
    }

    #[inline]
    pub fn take(self) -> (Vec<String>, Option<BasicCredConfig>) {
        (self.subject_name, self.inner.map(|x| *x))
    }
}

impl<Prin, Cred> BasicAuthNPrinConfig<Prin, Cred> {
    #[inline]
    pub fn new(
        prin: Prin,
        cred: Cred
    ) -> Self {
        BasicAuthNPrinConfig {
            prin: prin,
            cred: cred
        }
    }

    #[inline]
    pub fn prin(&self) -> &Prin {
        &self.prin
    }

    #[inline]
    pub fn cred(&self) -> &Cred {
        &self.cred
    }

    #[inline]
    pub fn take(self) -> (Prin, Cred) {
        (self.prin, self.cred)
    }
}

impl<Prin, Cred> TestAuthNPrinConfig<Prin, Cred> {
    #[inline]
    pub fn new(
        prin: Prin,
        cred: Vec<Cred>
    ) -> Self {
        TestAuthNPrinConfig {
            prin: prin,
            cred: cred
        }
    }

    #[inline]
    pub fn prin(&self) -> &Prin {
        &self.prin
    }

    #[inline]
    pub fn cred(&self) -> &[Cred] {
        &self.cred
    }

    #[inline]
    pub fn take(self) -> (Prin, Vec<Cred>) {
        (self.prin, self.cred)
    }
}

impl<Prin> BasicAuthNConfig<Prin> {
    #[inline]
    pub fn new(
        rules: Vec<BasicAuthNPrinConfig<Prin, BasicCredConfig>>,
        unsafe_opts: HostAuthNUnsafeConfig
    ) -> Self {
        BasicAuthNConfig {
            unsafe_opts: unsafe_opts,
            rules: rules
        }
    }

    #[inline]
    pub fn rules(&self) -> &[BasicAuthNPrinConfig<Prin, BasicCredConfig>] {
        &self.rules
    }

    #[inline]
    pub fn unsafe_opts(&self) -> &HostAuthNUnsafeConfig {
        &self.unsafe_opts
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Vec<BasicAuthNPrinConfig<Prin, BasicCredConfig>>,
        HostAuthNUnsafeConfig
    ) {
        (self.rules, self.unsafe_opts)
    }
}

impl HostAuthNUnsafeConfig {
    #[inline]
    pub fn allow_ip_addr_creds(&self) -> bool {
        self.allow_ip_addr_creds
    }
}

impl<Addr> Display for BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self.port {
            Some(port) => write!(f, "{}:{}", self.addr, port),
            None => write!(f, "{}:*", self.addr)
        }
    }
}

impl<Addr> Display for BadIPMatcher<Addr>
where
    Addr: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            BadIPMatcher::Addr { err } => err.fmt(f),
            BadIPMatcher::BadFormat { err } => {
                write!(f, "bad IP match specification \"{}\"", err)
            }
        }
    }
}

#[test]
fn test_deserialize_basic_cred_ssl_flat() {
    let yaml = concat!(
        "ssl:\n",
        "  subject-name:\n",
        "    - \"a\"\n",
        "    - \"b\"\n",
    );
    let expected = BasicCredConfig::SSL {
        ssl: BasicSSLCredConfig {
            subject_name: vec![String::from("a"), String::from("b")],
            inner: None
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_cred_ssl_unix() {
    let yaml = concat!(
        "ssl:\n",
        "  subject-name:\n",
        "    - \"a\"\n",
        "    - \"b\"\n",
        "  unix: path/to/nowhere.sock"
    );
    let expected = BasicCredConfig::SSL {
        ssl: BasicSSLCredConfig {
            subject_name: vec![String::from("a"), String::from("b")],
            inner: Some(Box::new(BasicCredConfig::Unix {
                unix: PathBuf::from("path/to/nowhere.sock")
            }))
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_cred_ssl_ip() {
    let yaml = concat!(
        "ssl:\n",
        "  subject-name:\n",
        "    - \"a\"\n",
        "    - \"b\"\n",
        "  unsafe:\n",
        "    ip: 10.10.10.10:1111"
    );
    let expected = BasicCredConfig::SSL {
        ssl: BasicSSLCredConfig {
            subject_name: vec![String::from("a"), String::from("b")],
            inner: Some(Box::new(BasicCredConfig::Unsafe {
                unsafe_cred: UnsafeBasicCredConfig::IP {
                    unsafe_ip: BasicIPMatcherConfig {
                        port: Some(1111),
                        addr: "10.10.10.10".parse().unwrap()
                    }
                }
            }))
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_cred_unix() {
    let yaml = concat!("unix: path/to/nowhere.sock");
    let expected = BasicCredConfig::Unix {
        unix: PathBuf::from("path/to/nowhere.sock")
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_matcher_ip4() {
    let actual = BasicIPMatcherConfig::<IpAddr>::try_from("10.10.10.10:1111")
        .expect("Expected success");
    let expected = BasicIPMatcherConfig {
        port: Some(1111),
        addr: "10.10.10.10".parse().unwrap()
    };

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_matcher_ip4_no_port() {
    let actual = BasicIPMatcherConfig::<IpAddr>::try_from("10.10.10.10:*")
        .expect("Expected success");
    let expected = BasicIPMatcherConfig {
        port: None,
        addr: "10.10.10.10".parse().unwrap()
    };

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_matcher_ip6() {
    let actual = BasicIPMatcherConfig::<IpAddr>::try_from(
        "1234:5678:90ab:cdef:1234:5678:90ab:cdef:1111"
    )
    .expect("Expected success");
    let expected = BasicIPMatcherConfig {
        port: Some(1111),
        addr: "1234:5678:90ab:cdef:1234:5678:90ab:cdef".parse().unwrap()
    };

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_matcher_ip6_no_port() {
    let actual = BasicIPMatcherConfig::<IpAddr>::try_from(
        "1234:5678:90ab:cdef:1234:5678:90ab:cdef:*"
    )
    .expect("Expected success");
    let expected = BasicIPMatcherConfig {
        port: None,
        addr: "1234:5678:90ab:cdef:1234:5678:90ab:cdef".parse().unwrap()
    };

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_matcher_ip6_brackets() {
    let actual = BasicIPMatcherConfig::<IpAddr>::try_from(
        "[1234:5678:90ab:cdef:1234:5678:90ab:cdef]:1111"
    )
    .expect("Expected success");
    let expected = BasicIPMatcherConfig {
        port: Some(1111),
        addr: "1234:5678:90ab:cdef:1234:5678:90ab:cdef".parse().unwrap()
    };

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_matcher_ip6_brackets_no_port() {
    let actual = BasicIPMatcherConfig::<IpAddr>::try_from(
        "[1234:5678:90ab:cdef:1234:5678:90ab:cdef]:*"
    )
    .expect("Expected success");
    let expected = BasicIPMatcherConfig {
        port: None,
        addr: "1234:5678:90ab:cdef:1234:5678:90ab:cdef".parse().unwrap()
    };

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_cred_ip() {
    let yaml = concat!("unsafe:\n", "  ip: 10.10.10.10:1111");
    let expected = BasicCredConfig::Unsafe {
        unsafe_cred: UnsafeBasicCredConfig::IP {
            unsafe_ip: BasicIPMatcherConfig {
                port: Some(1111),
                addr: "10.10.10.10".parse().unwrap()
            }
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_cred_ip_no_port() {
    let yaml = concat!("unsafe:\n", "  ip: 10.10.10.10:*");
    let expected = BasicCredConfig::Unsafe {
        unsafe_cred: UnsafeBasicCredConfig::IP {
            unsafe_ip: BasicIPMatcherConfig {
                port: None,
                addr: "10.10.10.10".parse().unwrap()
            }
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_cred_socks5() {
    let yaml = concat!("unsafe:\n", "  socks5: example.com:1111",);
    let expected = BasicCredConfig::Unsafe {
        unsafe_cred: UnsafeBasicCredConfig::SOCKS5 {
            unsafe_ip: BasicIPMatcherConfig {
                port: Some(1111),
                addr: IPEndpointAddr::Name(String::from("example.com"))
            }
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_authn_prin_config() {
    let yaml = concat!(
        "prin: test-prin\n",
        "cred:\n",
        "  ssl:\n",
        "    subject-name:\n",
        "      - \"a\"\n",
        "      - \"b\"\n",
        "    unsafe:\n",
        "      ip: 10.10.10.10:1111"
    );
    let expected = BasicAuthNPrinConfig {
        prin: String::from("test-prin"),
        cred: BasicCredConfig::SSL {
            ssl: BasicSSLCredConfig {
                subject_name: vec![String::from("a"), String::from("b")],
                inner: Some(Box::new(BasicCredConfig::Unsafe {
                    unsafe_cred: UnsafeBasicCredConfig::IP {
                        unsafe_ip: BasicIPMatcherConfig {
                            port: Some(1111),
                            addr: "10.10.10.10".parse().unwrap()
                        }
                    }
                }))
            }
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_authn_config_unsafe() {
    let yaml = concat!(
        "rules:\n",
        "  - prin: test-ssl-prin\n",
        "    cred:\n",
        "      ssl:\n",
        "        subject-name:\n",
        "          - \"a\"\n",
        "          - \"b\"\n",
        "        unsafe:\n",
        "          ip: 10.10.10.10:1111\n",
        "  - prin: test-unix-prin\n",
        "    cred:\n",
        "      unix: path/to/nowhere.sock\n",
        "unsafe:\n",
        "  allow-ip-addr-creds: true"
    );
    let expected = BasicAuthNConfig {
        rules: vec![
            BasicAuthNPrinConfig {
                prin: String::from("test-ssl-prin"),
                cred: BasicCredConfig::SSL {
                    ssl: BasicSSLCredConfig {
                        subject_name: vec![
                            String::from("a"),
                            String::from("b"),
                        ],
                        inner: Some(Box::new(BasicCredConfig::Unsafe {
                            unsafe_cred: UnsafeBasicCredConfig::IP {
                                unsafe_ip: BasicIPMatcherConfig {
                                    port: Some(1111),
                                    addr: "10.10.10.10".parse().unwrap()
                                }
                            }
                        }))
                    }
                }
            },
            BasicAuthNPrinConfig {
                prin: String::from("test-unix-prin"),
                cred: BasicCredConfig::Unix {
                    unix: PathBuf::from("path/to/nowhere.sock")
                }
            },
        ],
        unsafe_opts: HostAuthNUnsafeConfig {
            allow_ip_addr_creds: true
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_basic_authn_config() {
    let yaml = concat!(
        "rules:\n",
        "  - prin: test-ssl-prin\n",
        "    cred:\n",
        "      ssl:\n",
        "        subject-name:\n",
        "          - \"a\"\n",
        "          - \"b\"\n",
        "  - prin: test-unix-prin\n",
        "    cred:\n",
        "      unix: path/to/nowhere.sock\n",
    );
    let expected = BasicAuthNConfig {
        rules: vec![
            BasicAuthNPrinConfig {
                prin: String::from("test-ssl-prin"),
                cred: BasicCredConfig::SSL {
                    ssl: BasicSSLCredConfig {
                        subject_name: vec![
                            String::from("a"),
                            String::from("b"),
                        ],
                        inner: None
                    }
                }
            },
            BasicAuthNPrinConfig {
                prin: String::from("test-unix-prin"),
                cred: BasicCredConfig::Unix {
                    unix: PathBuf::from("path/to/nowhere.sock")
                }
            },
        ],
        unsafe_opts: HostAuthNUnsafeConfig {
            allow_ip_addr_creds: false
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}
