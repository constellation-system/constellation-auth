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

use std::collections::HashMap;
use std::convert::Infallible;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::string::FromUtf8Error;

use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::unix::UnixSocketAddr;
use log::debug;
use log::error;
use log::info;
use log::warn;

use crate::authn::AuthNResult;
use crate::authn::BasicAuthNed;
use crate::authn::SessionAuthN;
use crate::config::BasicAuthNConfig;
use crate::config::BasicCredConfig;
use crate::config::UnsafeBasicCredConfig;
use crate::cred::Credentials;
#[cfg(feature = "gssapi")]
use crate::cred::GSSAPICred;
use crate::cred::SSLCred;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BasicCred {
    IP {
        unsafe_addr: SocketAddr
    },
    Unix {
        addr: UnixSocketAddr
    },
    SSL {
        subject_name: Vec<String>,
        inner: Option<Box<BasicCred>>
    },
    #[cfg(feature = "gssapi")]
    GSSAPI {
        name: String
    }
}

enum BasicCredMatcherSSLEntry<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash {
    Prin { prin: Prin },
    Matcher { matcher: Box<BasicAuthN<Prin>> }
}

pub struct BasicAuthN<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash {
    unsafe_ip: Option<HashMap<SocketAddr, Prin>>,
    unix: Option<HashMap<UnixSocketAddr, Prin>>,
    ssl: Option<HashMap<Vec<String>, BasicCredMatcherSSLEntry<Prin>>>,
    #[cfg(feature = "gssapi")]
    gssapi: Option<HashMap<String, Prin>>
}

#[cfg(feature = "gssapi")]
#[derive(Debug)]
pub enum BasicCredGSSAPIError {
    GSSAPI { err: libgssapi::error::Error },
    UTF8 { err: FromUtf8Error }
}

#[derive(Debug)]
pub enum BasicAuthNCreateError {
    Cred {
        err: std::io::Error
    },
    DuplicateIP {
        addr: SocketAddr
    },
    DuplicateUnix {
        addr: UnixSocketAddr
    },
    DuplicateSSL {
        subject_name: Vec<String>
    },
    #[cfg(feature = "gssapi")]
    DuplicateGSSAPI {
        name: String
    }
}

#[derive(Debug)]
pub enum BasicAuthNError<Cred, Into> {
    Cred { err: Cred },
    Into { err: Into }
}

impl<Prin> Default for BasicAuthN<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash
{
    #[inline]
    fn default() -> Self {
        BasicAuthN {
            unsafe_ip: None,
            unix: None,
            ssl: None,
            #[cfg(feature = "gssapi")]
            gssapi: None
        }
    }
}

impl<Prin> BasicAuthN<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash
{
    fn match_cred(
        &self,
        cred: &BasicCred
    ) -> Option<&Prin> {
        match cred {
            // If unsafe options aren't allowed, no such entry will be
            // here.
            BasicCred::IP { unsafe_addr } => {
                self.unsafe_ip.as_ref().and_then(|tab| {
                    let out = tab.get(unsafe_addr);

                    if let Some(prin) = out {
                        warn!(target: "basic-authn-matcher",
                              "authenticating principal {} with unsafe IP \
                               address credential {} (this allows for trivial \
                               spoofing of channel credentials)",
                              prin, unsafe_addr);
                    } else {
                        debug!(target: "basic-authn-matcher",
                               "failed to match IP address {}",
                               unsafe_addr);
                    }

                    out
                })
            }
            BasicCred::Unix { addr } => self.unix.as_ref().and_then(|tab| {
                let out = tab.get(addr);

                if let Some(prin) = out {
                    debug!(target: "basic-authn-matcher",
                               "matched Unix socket address {} to {}",
                               addr, prin);
                } else {
                    debug!(target: "basic-authn-matcher",
                               "failed to match Unix socket address {}",
                               addr);
                }

                out
            }),
            BasicCred::SSL {
                subject_name,
                inner
            } => self
                .ssl
                .as_ref()
                .and_then(|tab| {
                    let out = tab.get(subject_name);

                    if out.is_none() {
                        debug!(target: "basic-authn-matcher",
                               "failed to match SSL subject name {}",
                               subject_name.join(","));
                    }

                    out
                })
                .and_then(|ent| match ent {
                    BasicCredMatcherSSLEntry::Prin { prin } => {
                        debug!(target: "basic-authn-matcher",
                               "matched SSL subject name {} to {}",
                               subject_name.join(","), prin);

                        Some(prin)
                    }
                    BasicCredMatcherSSLEntry::Matcher { matcher } => {
                        debug!(target: "basic-authn-matcher",
                               "matched SSL subject name {} to further \
                                requirements",
                               subject_name.join(","));

                        inner.as_ref().and_then(|inner| {
                            matcher.match_cred(inner.as_ref())
                        })
                    }
                }),
            #[cfg(feature = "gssapi")]
            BasicCred::GSSAPI { name } => self.gssapi.as_ref().and_then(|tab| {
                let out = tab.get(name);

                if let Some(prin) = out {
                    debug!(target: "basic-authn-matcher",
                               "matched GSSAPI principal {} to {}",
                               name, prin);
                } else {
                    debug!(target: "basic-authn-matcher",
                               "failed to match GSSAPI principal {}",
                               name);
                }

                out
            })
        }
    }

    fn insert(
        &mut self,
        cred: BasicCredConfig,
        prin: Prin,
        size_hint: usize,
        allow_unsafe_opts: bool
    ) -> Result<(), BasicAuthNCreateError> {
        match cred {
            BasicCredConfig::Unsafe {
                unsafe_cred: UnsafeBasicCredConfig::IP { unsafe_ip }
            } => {
                if allow_unsafe_opts {
                    warn!(target: "basic-authn-matcher",
                      "unsafe IP address credential for principal {} (this \
                       allows for trivial spoofing of channel credentials)",
                      prin);

                    match &mut self.unsafe_ip {
                        Some(map) => {
                            if map.insert(unsafe_ip, prin).is_some() {
                                return Err(
                                    BasicAuthNCreateError::DuplicateIP {
                                        addr: unsafe_ip
                                    }
                                );
                            }
                        }
                        None => {
                            let mut map = HashMap::with_capacity(size_hint);

                            if map.insert(unsafe_ip, prin).is_some() {
                                error!(target: "basic-authn-matcher",
                                   "HashMap should not contain any entries")
                            }

                            self.unsafe_ip = Some(map);
                        }
                    }
                } else {
                    info!(target: "basic-authn-matcher",
                      "ignorinng unsafe IP address credential because unsafe \
                       features have not been enabled")
                }
            }
            BasicCredConfig::Unix { unix } => {
                let addr = UnixSocketAddr::try_from(unix)
                    .map_err(|err| BasicAuthNCreateError::Cred { err: err })?;

                match &mut self.unix {
                    Some(map) => {
                        if map.insert(addr.clone(), prin).is_some() {
                            return Err(BasicAuthNCreateError::DuplicateUnix {
                                addr: addr
                            });
                        }
                    }
                    None => {
                        let mut map = HashMap::with_capacity(size_hint);

                        if map.insert(addr, prin).is_some() {
                            error!(target: "basic-authn-matcher",
                                   "HashMap should not contain any entries")
                        }

                        self.unix = Some(map);
                    }
                }
            }
            BasicCredConfig::SSL { ssl } => {
                let (subject_name, inner) = ssl.take();
                let ent = match inner {
                    Some(inner) => {
                        let mut matcher = Self::default();

                        matcher.insert(
                            inner,
                            prin,
                            size_hint,
                            allow_unsafe_opts
                        )?;

                        BasicCredMatcherSSLEntry::Matcher {
                            matcher: Box::new(matcher)
                        }
                    }
                    None => BasicCredMatcherSSLEntry::Prin { prin: prin }
                };

                match &mut self.ssl {
                    Some(map) => {
                        if map.insert(subject_name.clone(), ent).is_some() {
                            return Err(BasicAuthNCreateError::DuplicateSSL {
                                subject_name: subject_name
                            });
                        }
                    }
                    None => {
                        let mut map = HashMap::with_capacity(size_hint);

                        if map.insert(subject_name, ent).is_some() {
                            error!(target: "basic-authn-matcher",
                                   "HashMap should not contain any entries")
                        }

                        self.ssl = Some(map);
                    }
                }
            }
            #[cfg(feature = "gssapi")]
            BasicCredConfig::GSSAPI { gssapi } => {
                let name = gssapi.take();

                match &mut self.gssapi {
                    Some(map) => {
                        if map.insert(name.clone(), prin).is_some() {
                            return Err(
                                BasicAuthNCreateError::DuplicateGSSAPI {
                                    name: name
                                }
                            );
                        }
                    }
                    None => {
                        let mut map = HashMap::with_capacity(size_hint);

                        if map.insert(name, prin).is_some() {
                            error!(target: "basic-authn-matcher",
                                   "HashMap should not contain any entries")
                        }

                        self.gssapi = Some(map);
                    }
                }
            }
        }

        Ok(())
    }

    fn shrink_to_fit(&mut self) {
        if let Some(unsafe_ip) = &mut self.unsafe_ip {
            unsafe_ip.shrink_to_fit();
        }

        if let Some(unix) = &mut self.unix {
            unix.shrink_to_fit();
        }

        if let Some(ssl) = &mut self.ssl {
            ssl.shrink_to_fit();

            for ent in ssl.values_mut() {
                if let BasicCredMatcherSSLEntry::Matcher { matcher } = ent {
                    matcher.shrink_to_fit()
                }
            }
        }

        #[cfg(feature = "gssapi")]
        if let Some(gssapi) = &mut self.gssapi {
            gssapi.shrink_to_fit();
        }
    }
}

impl<Prin> CreateWithParam<bool> for BasicAuthN<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash
{
    type Config = BasicAuthNConfig<Prin>;
    type CreateError = BasicAuthNCreateError;

    fn create(
        config: Self::Config,
        allow_unsafe_opts: bool
    ) -> Result<Self, Self::CreateError> {
        let (rules, unsafe_opts) = config.take();
        let allow_unsafe_creds = if unsafe_opts.allow_unsafe_ip_creds() {
            if allow_unsafe_opts {
                warn!(target: "basic-authn",
                      "unsafe option allow-ip-addr-creds enabled for basic \
                       authenticator (this allows for trivial spoofing of \
                       channel credentials)");

                true
            } else {
                info!(target: "basic-authn",
                      "ignoring unsafe configuration option \
                       allow-ip-addr-creds because unsafe features have not \
                       been enabled");

                false
            }
        } else {
            false
        };
        let nrules = rules.len();
        let mut matcher = Self::default();

        for rule in rules {
            let (prin, cred) = rule.take();

            matcher.insert(cred, prin, nrules, allow_unsafe_creds)?;
        }

        matcher.shrink_to_fit();

        Ok(matcher)
    }
}

impl<Flow, Prin> Negotiator<AuthNResult<BasicAuthNed<Prin, Flow>, Flow>>
    for BasicAuthN<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash,
    Flow: Credentials + Read + Write,
    Flow::Cred: TryInto<BasicCred>
{
    type NegotiateError = Infallible;
    type Pending = Infallible;
    type State = AuthNResult<BasicAuthNed<Prin, Flow>, Flow>;

    /// Perform negotiations.
    #[inline]
    fn negotiate(
        &self,
        state: AuthNResult<BasicAuthNed<Prin, Flow>, Flow>
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<Prin, Flow>, Flow>,
            Self::Pending
        >,
        Self::NegotiateError
    > {
        Ok(NegotiatorResult::Complete(state))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<Prin, Flow>, Flow>,
            Self::Pending
        >,
        Self::NegotiateError
    > {
        panic!("This should never be called!")
    }
}

impl<Flow, Prin>
    NegotiatorStart<AuthNResult<BasicAuthNed<Prin, Flow>, Flow>, Flow>
    for BasicAuthN<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash,
    Flow: Credentials + Read + Write,
    Flow::Cred: TryInto<BasicCred>,
    Flow::CredError: ScopedError,
    <Flow::Cred as TryInto<BasicCred>>::Error: Debug + Display + ScopedError
{
    type Param = ();
    type StartError = BasicAuthNError<
        Flow::CredError,
        <Flow::Cred as TryInto<BasicCred>>::Error
    >;

    #[inline]
    fn start(
        &self,
        _param: &(),
        stream: Flow
    ) -> Result<AuthNResult<BasicAuthNed<Prin, Flow>, Flow>, Self::StartError>
    {
        match stream
            .creds()
            .map_err(|err| BasicAuthNError::Cred { err: err })?
            .map(|cred| cred.try_into())
            .transpose()
            .map_err(|err| BasicAuthNError::Into { err: err })?
            .and_then(|cred| self.match_cred(&cred))
        {
            Some(prin) => {
                let authned = BasicAuthNed::new(prin.clone(), stream);

                Ok(AuthNResult::Accept(authned))
            }
            None => Ok(AuthNResult::Reject(stream))
        }
    }
}

impl<Flow, Prin> SessionAuthN<Flow> for BasicAuthN<Prin>
where
    Prin: Clone + Debug + Display + Eq + Hash,
    Flow: Credentials + Read + Write,
    Flow::Cred: TryInto<BasicCred>,
    Flow::CredError: ScopedError,
    <Flow::Cred as TryInto<BasicCred>>::Error: Debug + Display + ScopedError
{
    type AuthNSession = BasicAuthNed<Prin, Flow>;
    type Prin = Prin;
}

#[cfg(feature = "gssapi")]
impl TryFrom<GSSAPICred> for BasicCred {
    type Error = BasicCredGSSAPIError;

    fn try_from(val: GSSAPICred) -> Result<Self, Self::Error> {
        let name = val
            .src_name()
            .display_name()
            .map_err(|err| BasicCredGSSAPIError::GSSAPI { err: err })?;
        let name = String::from_utf8(name.to_vec())
            .map_err(|err| BasicCredGSSAPIError::UTF8 { err: err })?;

        Ok(BasicCred::GSSAPI { name: name })
    }
}

impl<Cred> TryFrom<SSLCred<Cred>> for BasicCred
where
    BasicCred: From<Cred>
{
    type Error = openssl::ssl::Error;

    fn try_from(val: SSLCred<Cred>) -> Result<Self, Self::Error> {
        let (inner, _, cert, _, _) = val.take();
        let inner = inner.map(BasicCred::from).map(Box::new);
        let subject_name: Result<Vec<String>, openssl::ssl::Error> = cert
            .subject_name()
            .entries()
            .map(|ent| {
                ent.data().to_string().map_err(openssl::ssl::Error::from)
            })
            .collect();

        Ok(BasicCred::SSL {
            subject_name: subject_name?,
            inner: inner
        })
    }
}

impl<Cred, Into> ScopedError for BasicAuthNError<Cred, Into>
where
    Cred: ScopedError,
    Into: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            BasicAuthNError::Cred { err } => err.scope(),
            BasicAuthNError::Into { err } => err.scope()
        }
    }
}

impl Display for BasicCredGSSAPIError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            BasicCredGSSAPIError::GSSAPI { err } => write!(f, "{}", err),
            BasicCredGSSAPIError::UTF8 { err } => write!(f, "{}", err)
        }
    }
}

impl<Cred, Into> Display for BasicAuthNError<Cred, Into>
where
    Cred: Display,
    Into: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            BasicAuthNError::Cred { err } => err.fmt(f),
            BasicAuthNError::Into { err } => err.fmt(f)
        }
    }
}

impl Display for BasicCred {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            BasicCred::IP { unsafe_addr } => write!(f, "ip://{}", unsafe_addr),
            BasicCred::Unix { addr } => write!(f, "unix://{}", addr),
            BasicCred::SSL {
                subject_name,
                inner: Some(inner)
            } => {
                write!(f, "ssl({}, {})", inner, subject_name.join(","))
            }
            BasicCred::SSL {
                subject_name,
                inner: None
            } => {
                write!(f, "ssl({})", subject_name.join(","))
            }
            BasicCred::GSSAPI { name } => write!(f, "gssapi({})", name)
        }
    }
}

impl Display for BasicAuthNCreateError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            BasicAuthNCreateError::Cred { err } => {
                write!(f, "error converting unix socket addr: {}", err)
            }
            BasicAuthNCreateError::DuplicateIP { addr } => {
                write!(f, "duplicate IP address credential: {}", addr)
            }
            BasicAuthNCreateError::DuplicateUnix { addr } => {
                write!(f, "duplicate unix socket credential: {}", addr)
            }
            BasicAuthNCreateError::DuplicateSSL { subject_name } => {
                write!(
                    f,
                    "duplicate SSL credential: {}",
                    subject_name.join(",")
                )
            }
            BasicAuthNCreateError::DuplicateGSSAPI { name } => {
                write!(f, "duplicate GSSAPI credential: {}", name)
            }
        }
    }
}
