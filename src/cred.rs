// Copyright © 2024-25 The Johns Hopkins Applied Physics Laboratory LLC.
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

//! Credential-harvesting functionality.
use std::convert::Infallible;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
#[cfg(feature = "unix")]
use std::io::Error;
#[cfg(feature = "openssl")]
use std::io::Read;
#[cfg(feature = "openssl")]
use std::io::Write;
use std::net::TcpStream;
#[cfg(feature = "unix")]
use std::os::unix::net::SocketAddr;
#[cfg(feature = "unix")]
use std::os::unix::net::UCred;
#[cfg(feature = "unix")]
use std::os::unix::net::UnixStream;

#[cfg(feature = "gssapi")]
use libgssapi::context::ClientCtx;
#[cfg(feature = "gssapi")]
use libgssapi::context::CtxFlags;
#[cfg(feature = "gssapi")]
use libgssapi::context::SecurityContext;
#[cfg(feature = "gssapi")]
use libgssapi::context::ServerCtx;
#[cfg(feature = "gssapi")]
use libgssapi::name::Name;
#[cfg(feature = "gssapi")]
use libgssapi::oid::Oid;
#[cfg(feature = "openssl")]
use openssl::ssl::SslStream;
#[cfg(feature = "openssl")]
use openssl::x509::X509;

/// Trait for types having auntentication credentials.
pub trait Credentials {
    /// Type of credentials.
    type Cred;
    /// Type of error that can occur obtaining credentials.
    type CredError: Debug + Display;

    /// Get credentials for this object.
    fn creds(&self) -> Result<Option<Self::Cred>, Self::CredError>;
}

/// Trait for types having auntentication credentials, requiring a
/// mutable reference.
///
/// This largely exists for GSSAPI functions.
pub trait CredentialsMut {
    /// Type of credentials.
    type Cred;
    /// Type of error that can occur obtaining credentials.
    type CredError: Debug + Display;

    /// Get credentials for this object.
    fn creds(&mut self) -> Result<Option<Self::Cred>, Self::CredError>;
}

#[cfg(feature = "gssapi")]
/// Credentials from a GSSAPI session.
pub struct GSSAPICred {
    /// Name used by us.
    src_name: Name,
    /// Counterparty name.
    target_name: Name,
    /// Authentication mechanism.
    mech: &'static Oid,
    /// Session flags.
    flags: CtxFlags,
    /// Whether the session is local.
    local: bool
}

#[cfg(feature = "openssl")]
/// Credentials from a TLS session.
pub struct SSLCred<S> {
    /// Credentials from inner stream.
    inner: Option<S>,
    session_id: Vec<u8>,
    peer_cert: X509,
    peer_cert_chain: Option<Vec<X509>>,
    /// Security level of the TLS session.
    seclvl: u32
}

/// Null credential, used for testing.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NullCred;

#[cfg(feature = "unix")]
pub struct UnixSocketCred<U> {
    local: SocketAddr,
    peer: SocketAddr,
    user: U
}

#[cfg(feature = "unix")]
impl<U> UnixSocketCred<U> {
    /// Get the local socket address.
    #[inline]
    pub fn local(&self) -> &SocketAddr {
        &self.local
    }

    /// Get the peer socket address.
    #[inline]
    pub fn peer(&self) -> &SocketAddr {
        &self.peer
    }

    /// Get the user information.
    #[inline]
    pub fn user(&self) -> &U {
        &self.user
    }
}

#[cfg(feature = "gssapi")]
impl GSSAPICred {
    /// Get the source principal name.
    #[inline]
    pub fn src_name(&self) -> &Name {
        &self.src_name
    }

    /// Get the counterparty principal name.
    #[inline]
    pub fn target_name(&self) -> &Name {
        &self.target_name
    }

    /// Get the authentication mechanism.
    #[inline]
    pub fn mech(&self) -> &'static Oid {
        self.mech
    }

    /// Get the flags.
    #[inline]
    pub fn flags(&self) -> &CtxFlags {
        &self.flags
    }

    /// Get whether this is a local session.
    #[inline]
    pub fn local(&self) -> bool {
        self.local
    }
}

#[cfg(feature = "openssl")]
impl<S> SSLCred<S> {
    /// Get the credentials for the underlying channel.
    #[inline]
    pub fn inner(&self) -> Option<&S> {
        self.inner.as_ref()
    }

    /// Get the SSL session ID.
    #[inline]
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Get the counterparty's certificate.
    #[inline]
    pub fn peer_cert(&self) -> &X509 {
        &self.peer_cert
    }

    /// Get the counterparty's certificate chain.
    #[inline]
    pub fn peer_cert_chain(&self) -> Option<&[X509]> {
        self.peer_cert_chain.as_deref()
    }

    /// Get the security level of the TLS session.
    #[inline]
    pub fn seclvl(&self) -> u32 {
        self.seclvl
    }
}

impl Credentials for TcpStream {
    type Cred = Infallible;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Infallible>, Infallible> {
        Ok(None)
    }
}

impl CredentialsMut for TcpStream {
    type Cred = Infallible;
    type CredError = Infallible;

    #[inline]
    fn creds(&mut self) -> Result<Option<Infallible>, Infallible> {
        <Self as Credentials>::creds(self)
    }
}

#[cfg(feature = "gssapi")]
impl CredentialsMut for ClientCtx {
    type Cred = GSSAPICred;
    type CredError = libgssapi::error::Error;

    #[inline]
    fn creds(&mut self) -> Result<Option<GSSAPICred>, Self::CredError> {
        if self.open()? && self.is_complete() {
            Ok(Some(GSSAPICred {
                src_name: self.source_name()?,
                target_name: self.target_name()?,
                mech: self.mechanism()?,
                flags: self.flags()?,
                local: self.local()?
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(feature = "gssapi")]
impl CredentialsMut for ServerCtx {
    type Cred = GSSAPICred;
    type CredError = libgssapi::error::Error;

    #[inline]
    fn creds(&mut self) -> Result<Option<GSSAPICred>, Self::CredError> {
        if self.open()? && self.is_complete() {
            Ok(Some(GSSAPICred {
                src_name: self.source_name()?,
                target_name: self.target_name()?,
                mech: self.mechanism()?,
                flags: self.flags()?,
                local: self.local()?
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(feature = "openssl")]
impl<S> Credentials for SslStream<S>
where
    S: Credentials + Read + Write
{
    type Cred = SSLCred<S::Cred>;
    type CredError = S::CredError;

    #[inline]
    fn creds(&self) -> Result<Option<Self::Cred>, S::CredError> {
        let inner = self.get_ref().creds()?;
        let ssl = self.ssl();
        let seclvl = ssl.security_level();

        Ok(ssl
            .peer_certificate()
            .and_then(|peer_cert| {
                ssl.session().map(|session| (peer_cert, session.id()))
            })
            .map(|(peer_cert, session_id)| {
                let chain = ssl.verified_chain().map(|stack| {
                    stack.into_iter().map(|cert| cert.to_owned()).collect()
                });

                SSLCred {
                    inner: inner,
                    session_id: session_id.to_vec(),
                    peer_cert: peer_cert,
                    peer_cert_chain: chain,
                    seclvl: seclvl
                }
            }))
    }
}

#[cfg(feature = "openssl")]
impl<S> CredentialsMut for SslStream<S>
where
    S: Credentials + Read + Write
{
    type Cred = SSLCred<S::Cred>;
    type CredError = S::CredError;

    #[inline]
    fn creds(&mut self) -> Result<Option<Self::Cred>, S::CredError> {
        <Self as Credentials>::creds(self)
    }
}

#[cfg(feature = "unix")]
impl Credentials for UnixStream {
    type Cred = UnixSocketCred<UCred>;
    type CredError = Error;

    #[inline]
    fn creds(&self) -> Result<Option<Self::Cred>, Error> {
        let local = self.local_addr()?;
        let peer = self.peer_addr()?;
        let user = self.peer_cred()?;

        Ok(Some(UnixSocketCred {
            local: local,
            peer: peer,
            user: user
        }))
    }
}

#[cfg(feature = "unix")]
impl CredentialsMut for UnixStream {
    type Cred = UnixSocketCred<UCred>;
    type CredError = Error;

    #[inline]
    fn creds(&mut self) -> Result<Option<Self::Cred>, Error> {
        <Self as Credentials>::creds(self)
    }
}

#[cfg(feature = "unix")]
impl Credentials for mio::net::UnixStream {
    type Cred = UnixSocketCred<()>;
    type CredError = Error;

    #[inline]
    fn creds(&self) -> Result<Option<Self::Cred>, Error> {
        let local = self.local_addr()?;
        let peer = self.peer_addr()?;

        Ok(Some(UnixSocketCred {
            local: local,
            peer: peer,
            user: ()
        }))
    }
}

#[cfg(feature = "unix")]
impl CredentialsMut for mio::net::UnixStream {
    type Cred = UnixSocketCred<()>;
    type CredError = Error;

    #[inline]
    fn creds(&mut self) -> Result<Option<Self::Cred>, Error> {
        <Self as Credentials>::creds(self)
    }
}

impl Display for NullCred {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "null credential")
    }
}
