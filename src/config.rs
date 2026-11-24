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

//! Configuration objects.
//!
//! This module provides configuration objects for creating various
//! types in this crate.  Configuration objects support
//! serialization/deserialization through [`serde`], and are designed
//! specifically to be serialized and deserialized as YAML using
//! `yaml_serde`.

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

/// Configuration object for credentials for
/// [`TestAuthn`](crate::authn::test::TestAuthN).
///
/// This specifies an IP address or Unix socket name as a credential.
/// This can be seen as a more limited analogue of [`BasicCredConfig`].
///
/// This is used primarily for testing purposes.  This may be removed
/// in the future.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "test-cred")]
#[serde(untagged)]
pub enum TestCredConfig {
    /// An IP address credential.
    IP {
        /// The IP address configuration.
        ip: UnsafeBasicCredConfig
    },
    /// A Unix socket path.
    Unix {
        /// The Unix socket path.
        unix: PathBuf
    }
}

/// Configuration object for a specific principal for
/// [`TestAuthN`](crate::authn::test::TestAuthN).
///
/// This maps a single principal to a set of
/// [`TestCredConfig`]s.
///
/// This is used primarily for testing purposes.  This may be removed
/// in the future.
#[doc(hidden)]
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "test-authn-config")]
#[serde(rename_all = "kebab-case")]
pub struct TestAuthNPrinConfig<Prin, Cred> {
    prin: Prin,
    cred: Vec<Cred>
}

/// Basic credential configuration.
///
/// This specifies a credential for use in
/// [`BasicAuthN`](crate::authn::basic::BasicAuthN).  This will be
/// matched with harvested credentials in the `BasicAuthN`
/// authentication process.
///
/// # YAML Format
///
/// The YAML format consists of one of the variants, along with the
/// appropriate content.  The variants' names are as follows:
///
/// - `unsafe`: Unsafe configuration options.  The content is an
///   [`UnsafeBasicCredConfig`].
///
/// - `unix`: A Unix socket credential.  The content is the Unix socket's path.
///
/// - `ssl`: An SSL credential.  The content is a [`BasicSSLCredConfig`].
///
/// - `gssapi`: A GSSAPI credential.  The content is a
///   [`BasicGSSAPICredConfig`].
///
/// # Examples
///
/// The following specifies a Unix socket path
/// ```yaml
/// unix: '/var/run/example.sock'
/// ```
///
/// The following specifies an IP address:
/// ```yaml
/// unsafe:
///   ip: '10.10.10.10:1337'
/// ```
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "basic-cred")]
#[serde(untagged)]
pub enum BasicCredConfig {
    /// Unsafe credential types.
    ///
    /// This exists primarily to force unsafe options to be explicitly
    /// labeled "unsafe" in configuration files.  *Changes removing
    /// this requirement must be summarily rejected*.
    Unsafe {
        /// The unsafe configuration options.
        ///
        /// This is renamed to `unsafe` for [`serde`] purposes.
        #[serde(rename = "unsafe")]
        unsafe_cred: UnsafeBasicCredConfig
    },
    /// A Unix socket credential.
    ///
    /// At present this consists of the Unix socket path.  In the
    /// future, this may also be able to specify a user and a group
    /// for the peer credentials.
    Unix {
        /// The Unix socket path.
        unix: PathBuf
    },
    /// SSL credentials.
    ///
    /// This specifies a subset of credentials that can be harvested
    /// from a TLS session.
    SSL {
        /// Expected TLS credentials.
        ssl: BasicSSLCredConfig
    },
    #[cfg(feature = "gssapi")]
    /// SSL credentials.
    ///
    /// This specifies a subset of credentials that can be harvested
    /// from a GSSAPI session.
    GSSAPI {
        /// Expected GSSAPI credentials.
        gssapi: BasicGSSAPICredConfig
    }
}

/// Specification for an IP address and port credential.
///
/// This specifies an IP address and a port, with the port being optional.
///
/// # Type Parameters
///
/// - `Addr`: Concrete type of addresses.  This is usually [`IpAddr`] or
///   [`IPEndpointAddr`].
///
/// # Format
///
/// The serialized format is a single string of the form `addr:port`
/// if a port is specified, or `addr:*` if one is not.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "unsafe-basic-ip-matcher")]
#[serde(rename_all = "kebab-case")]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display {
    /// The port, if one is given.
    port: Option<u16>,
    /// The address.
    addr: Addr
}

/// Unsafe credential configuration.
///
/// This contains all credential options that are fundamentally unsafe
/// (i.e. they cannot be secured against spoofing).  At present, this
/// consists of IP address credentials.
///
/// # Usage
///
/// Use of these configuration options requires multiple "safety
/// switch" configuration parameters to be set:
///
/// - The `allow-ip-addr-creds` option must be set to `true` in the
///   [`BasicAuthNConfig`].
///
/// - The `allow-ip-addr-creds` option must *also* be set in any socket
///   configurations to actually generate IP address credentials.
///
/// - The [`BasicAuthN::create`](constellation_common::config::CreateWithParam::create) function
///   must be called with arguments explicitly permitting unsafe
///   options.
///
/// Use of these options will *always* generate warning log messages.
/// If the right options have not been given elsewhere, then warnings
/// will be generated about ignoring this configuration.  If the right
/// options have been given, then warnings will still be generated
/// about using an unsafe configuration.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "unsafe-basic-cred")]
#[serde(untagged)]
pub enum UnsafeBasicCredConfig {
    /// An IP address configuration.
    ///
    /// This will match both regular IP and SOCKS5 addresses; however,
    /// its structure *requires* a bare IP address (not a name).
    /// Names are not available from regular IP channels, and can only
    /// be specified with the `socks5` option.
    ///
    /// Bare IP addresses can be trivially spoofed and thus are
    /// unsafe.
    IP {
        /// Matching configuration for the IP address.
        #[serde(rename = "ip")]
        unsafe_ip: BasicIPMatcherConfig<IpAddr>
    },
    /// A SOCKS5 endpoint address
    ///
    /// This option permits specification of a name-based peer
    /// address.
    SOCKS5 {
        /// Matching configuration for the IP address.
        #[serde(rename = "socks5")]
        unsafe_ip: BasicIPMatcherConfig<IPEndpointAddr>
    }
}

/// Credential matching configuration for a TLS session.
///
/// *This configuration object is incomplete and will likely be expanded*.
///
/// # YAML Format
///
/// The YAML format consists of the following fields:
///
/// - `subject-name`: The Subject Name (SN) parameter from the TLS session.
///
/// - All fields from the matching configuration for the inner channel type are
///   included directly.  If none are given, the default values will be used
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "basic-ssl-cred")]
#[serde(rename_all = "kebab-case")]
pub struct BasicSSLCredConfig {
    /// The SSL Subject Name (SN) for the session.
    subject_name: Vec<String>,
    /// The credentials for the underlying session.
    #[serde(flatten)]
    #[serde(default)]
    inner: Option<Box<BasicCredConfig>>
}

#[cfg(feature = "gssapi")]
/// Credential matching configuration for a GSSAPI session.
///
/// *This configuration object is incomplete and will likely be expanded*.
///
/// # YAML Format
///
/// The YAML format consists of the following field:
///
/// - `name`: The subject name for the GSSAPI session.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-ssl-cred")]
#[serde(rename_all = "kebab-case")]
pub struct BasicGSSAPICredConfig {
    /// The subject name for the GSSAPI session.
    name: String
}

/// Matching configuration for a single principal for use in
/// [`BasicAuthN`](crate::authn::basic::BasicAuthN).
///
/// This pairs a principal to a credential matching scheme.
///
/// # Type Parameters
///
/// - `Prin`: Type of principals.
///
/// - `Cred` Type of credential matching.
///
/// # YAML Format
///
/// The YAML format has two fields:
///
/// - `prin`: The configuration for the principal.
///
/// - `cred`: The configuration for the credential-matching scheme.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-authn-config")]
#[serde(rename_all = "kebab-case")]
pub struct BasicAuthNPrinConfig<Prin, Cred> {
    /// The principal.
    prin: Prin,
    /// The credential-matching configuration.
    cred: Cred
}

/// Unsafe configuration flags for
/// [`BasicAuthN`](crate::authn::basic::BasicAuthN).
///
/// At present, this consists solely of the option to allow IP address
/// credentials.
///
/// # Usage
///
/// Use of these configuration options requires multiple "safety
/// switch" configuration parameters to be set:
///
/// - The `allow-ip-addr-creds` option must *also* be set in any socket
///   configurations to actually generate IP address credentials.
///
/// - The [`BasicAuthN::create`](constellation_common::config::CreateWithParam::create) function
///   must be called with arguments explicitly permitting unsafe
///   options.
///
/// Use of these options will *always* generate warning log messages.
/// If the argument to enable unsafe mode has not been given, then
/// warnings will be generated about ignoring this configuration.  If
/// the right options have been given, then warnings will still be
/// generated about using an unsafe configuration.
///
/// # YAML Format
///
/// The YAML format has one field:
///
/// - `allow-ip-addr-creds`: A boolean indicating whether to permit the use of
///   IP address credentials.
///
/// # Example
///
/// The following sets the option to allow IP address credentials:
/// ```yaml
/// allow-ip-addr-creds: true
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct HostAuthNUnsafeConfig {
    /// Whether or not to allow IP address credentials.
    allow_ip_addr_creds: bool
}

/// Top-level configuration object for
/// [`BasicAuthN`](crate::authn::basic::BasicAuthN).
///
/// This configures a simple matching authenticator that matches
/// harvested credentials to principals.
///
/// # YAML Format
///
/// The YAML format has two fields:
///
/// - `rules`: A sequence of [`BasicAuthNPrinConfig`]s giving rules for matching
///   harvested credentials to principals.  Multiple rules may be given for a
///   single principal, but only a single rule may exist for any given
///   credential.
///
/// - `unsafe`: A [`HostAuthNUnsafeConfig`] giving unsafe configuration options.
///   This is optional, and defaults to the safe options.
///
/// # Examples
///
/// The following example is taken from demo config permitting unsafe
/// credentials:
/// ```yaml
/// rules:
///   - prin: test-principal
///     cred:
///       unix: /var/run/example.sock
///
///   - prin: test-principal
///     cred:
///       unsafe:
///         ip: '[::1]:1337'
///
/// unsafe:
///   allow-ip-addr-creds: true
/// ```
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename = "basic-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct BasicAuthNConfig<Prin> {
    /// Credential-to-principal matching rules.
    ///
    /// Multiple rules may reference the same `Prin`, but rules
    /// must be unique to a given [`BasicCredConfig`].
    rules: Vec<BasicAuthNPrinConfig<Prin, BasicCredConfig>>,
    /// Unsafe options.
    ///
    /// This exists solely to force unsafe options to be explicitly
    /// labeled in the configuration.  *Changes removing this
    /// requirement must be summarily rejected*.
    #[serde(default)]
    #[serde(rename = "unsafe")]
    unsafe_opts: HostAuthNUnsafeConfig
}

/// Top-level configuration object for
/// [`TestAuthN`](crate::authn::test::TestAuthN).
///
/// This is primarily used for testing purposes.
#[doc(hidden)]
pub type TestAuthNConfig<Prin, Cred> = Vec<TestAuthNPrinConfig<Prin, Cred>>;

/// Errors that can occur parsing a [`BasicIPMatcherConfig`].
#[derive(Debug)]
pub enum BadIPMatcher<Addr> {
    /// An error occurred parsing the address.
    Addr {
        /// The error that occurred parsing the address.
        err: Addr
    },
    /// The string had a bad overall format.
    BadFormat {
        /// The original string.
        err: String
    }
}

impl<Addr> BasicIPMatcherConfig<Addr>
where
    Addr: Clone + Display + FromStr,
    Addr::Err: Display
{
    /// Create a `BasicIPMatcherConfig` from its components.
    ///
    /// # Parameters
    ///
    /// - `addr`: The address.
    ///
    /// - `port`: The port number, or `None` for wildcard matching of ports.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::convert::TryFrom;
    /// # use std::net::IpAddr;
    /// # use constellation_auth::config::BasicIPMatcherConfig;
    ///
    /// let addr: IpAddr = "10.10.10.10".parse().unwrap();
    ///
    /// assert_eq!(
    ///   BasicIPMatcherConfig::try_from("10.10.10.10:1337").unwrap(),
    ///   BasicIPMatcherConfig::new(addr, Some(1337))
    /// );
    ///
    /// assert_eq!(
    ///   BasicIPMatcherConfig::try_from("10.10.10.10:*").unwrap(),
    ///   BasicIPMatcherConfig::new(addr, None)
    /// );
    /// ```
    #[inline]
    pub fn new(
        addr: Addr,
        port: Option<u16>
    ) -> Self {
        BasicIPMatcherConfig {
            addr: addr,
            port: port
        }
    }

    /// Get the address.
    #[inline]
    pub fn addr(&self) -> &Addr {
        &self.addr
    }

    /// Get the port number, if there is one.
    #[inline]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Decompose this `BasicIPMatcherConfig` into an address and
    /// optional port.
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
    /// Create a new `BasicGSSAPICredConfig` from its components.
    ///
    /// # Parameters
    ///
    /// - `name`: The GSSAPI principal name.
    #[inline]
    pub fn new(name: String) -> Self {
        BasicGSSAPICredConfig { name: name }
    }

    /// Get the GSSAPI principal name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Decompose this `BasicGSSAPICredConfig` into its principal name.
    #[inline]
    pub fn take(self) -> String {
        self.name
    }
}

impl BasicSSLCredConfig {
    /// Create a `BasicSSLCredConfig` from its components.
    ///
    /// # Parameters
    ///
    /// - `subject_name`: The TLS subject name.
    ///
    /// - `inner`: The inner channel's credentials.
    ///
    /// # Example
    ///
    /// ```
    /// # use constellation_auth::config::BasicSSLCredConfig;
    ///
    /// let yaml = concat!(
    ///     "subject-name:\n",
    ///     "  - 'a'\n",
    ///     "  - 'b'",
    /// );
    /// let subject_name = vec![String::from("a"), String::from("b")];
    /// let expected: BasicSSLCredConfig = yaml_serde::from_str(yaml).unwrap();
    /// let actual = BasicSSLCredConfig::new(subject_name, None);
    ///
    /// assert_eq!(expected, actual);
    /// ```
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

    /// Get the TLS subject name.
    #[inline]
    pub fn subject_name(&self) -> &[String] {
        &self.subject_name
    }

    /// Get the inner channel's harvested credentials.
    #[inline]
    pub fn inner(&self) -> Option<&BasicCredConfig> {
        self.inner.as_deref()
    }

    /// Decompose this `BasicSSLCredConfig` into its components.
    ///
    /// # Return Value
    ///
    /// A pair consisting of the following:
    ///
    /// 1. The subject name.
    ///
    /// 1. The inner credentials.
    #[inline]
    pub fn take(self) -> (Vec<String>, Option<BasicCredConfig>) {
        (self.subject_name, self.inner.map(|x| *x))
    }
}

impl<Prin, Cred> BasicAuthNPrinConfig<Prin, Cred> {
    /// Create a `BasicAuthNPrinConfig` from its components.
    ///
    /// # Parameters
    ///
    /// - `prin`: The principal.
    ///
    /// - `cred`: The credential-matching configuration.
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

    /// Get the principal.
    #[inline]
    pub fn prin(&self) -> &Prin {
        &self.prin
    }

    /// Get the credential-matching configuration.
    #[inline]
    pub fn cred(&self) -> &Cred {
        &self.cred
    }

    /// Decompose this `BasicAuthNPrinConfig` into its components.
    ///
    /// # Return Value
    ///
    /// A pair consisting of the following:
    ///
    /// 1. The principal.
    ///
    /// 1. The credential-matching configuration.
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
    /// Create a `BasicAuthNConfig` from its components.
    ///
    /// # Parameters
    ///
    /// - `subject_name`: The TLS subject name.
    ///
    /// - `inner`: The inner channel's credentials.
    ///
    /// # Example
    ///
    /// ```
    /// # use constellation_auth::config::BasicAuthNConfig;
    /// # use constellation_auth::config::BasicAuthNPrinConfig;
    /// # use constellation_auth::config::BasicCredConfig;
    /// # use constellation_auth::config::BasicSSLCredConfig;
    /// # use constellation_auth::config::HostAuthNUnsafeConfig;
    ///
    /// let yaml = concat!(
    ///     "rules:\n",
    ///     "  - prin: 'test-prin'\n",
    ///     "    cred:\n",
    ///     "      ssl:\n",
    ///     "        subject-name:\n",
    ///     "          - \"a\"\n",
    ///     "          - \"b\"\n",
    ///     "unsafe:\n",
    ///     "  allow-ip-addr-creds: true"
    /// );
    /// let subject_name = vec![String::from("a"), String::from("b")];
    /// let ssl = BasicSSLCredConfig::new(subject_name, None);
    /// let cred = BasicCredConfig::SSL { ssl: ssl };
    /// let rule = BasicAuthNPrinConfig::new(String::from("test-prin"), cred);
    /// let unsafe_opts = HostAuthNUnsafeConfig::new(true);
    /// let expected: BasicAuthNConfig<String> =
    ///     yaml_serde::from_str(yaml).unwrap();
    /// let actual = BasicAuthNConfig::new(vec![rule], unsafe_opts);
    ///
    /// assert_eq!(expected, actual);
    /// ```
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

    /// Get the authentication rules.
    #[inline]
    pub fn rules(&self) -> &[BasicAuthNPrinConfig<Prin, BasicCredConfig>] {
        &self.rules
    }

    /// Get the unsafe options.
    #[inline]
    pub fn unsafe_opts(&self) -> &HostAuthNUnsafeConfig {
        &self.unsafe_opts
    }

    /// Decompose this `BasicAuthNConfig` into its components.
    ///
    /// # Return Value
    ///
    /// A pair consisting of the following:
    ///
    /// 1. The authentication rules.
    ///
    /// 1. The unsafe options.
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
    /// Create a `HostAuthNUnsafeConfig` from its components.
    ///
    /// # Parameters
    ///
    /// - `allow_ip_addr_creds`: Whether IP address credentials are allowed.
    ///
    /// # Example
    ///
    /// ```
    /// # use constellation_auth::config::HostAuthNUnsafeConfig;
    ///
    /// let yaml = concat!(
    ///     "allow-ip-addr-creds: true"
    /// );
    /// let expected: HostAuthNUnsafeConfig =
    ///     yaml_serde::from_str(yaml).unwrap();
    /// let actual = HostAuthNUnsafeConfig::new(true);
    ///
    /// assert_eq!(expected, actual);
    /// ```
    #[inline]
    pub fn new(allow_ip_addr_creds: bool) -> Self {
        HostAuthNUnsafeConfig {
            allow_ip_addr_creds: allow_ip_addr_creds
        }
    }

    /// Get whether IP address credentials are allowed.
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
