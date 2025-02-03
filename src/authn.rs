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

//! Authentication traits.
use std::collections::HashMap;
use std::convert::Infallible;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::Arc;

use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::nonblock::NonblockResult;
use log::trace;

use crate::cred::Credentials;
use crate::cred::NullCred;

/// Receiver for authenticated messages.
pub trait AuthNMsgRecv<Prin, Msg> {
    /// Errors that can occur reporting messages.
    type RecvError: Display + ScopedError;

    /// Receive an authenticated message.
    fn recv_auth_msg(
        &mut self,
        prin: &Prin,
        msg: Msg
    ) -> Result<(), Self::RecvError>;
}

/// Trait for session authenticators.
///
/// These authenticators have access to the raw underlying session,
/// and are able to execute sub-protocols in order to perform
/// authentication.  They are also able to harvest credentials from
/// the session in order to perform authentication.
///
/// The result of successful authentication should be a session
/// principal.
pub trait SessionAuthN<Flow: Credentials + Read + Write> {
    /// Type of session prinicpals.
    type Prin: Clone + Display + Eq + Hash;
    /// Type of errors that can occur during authentication.
    type Error: Display + ScopedError;

    /// Attempt to perform session authentication without blocking.
    ///
    /// This will return an [AuthNResult] containing a
    /// [Prin](SessionAuthN::Prin) in the case of success.
    fn session_authn_nonblock(
        &self,
        flow: &mut Flow
    ) -> Result<NonblockResult<AuthNResult<Self::Prin>, ()>, Self::Error>;

    /// Perform session authentication.
    ///
    /// This will return an [AuthNResult] containing a
    /// [Prin](SessionAuthN::Prin) in the case of success.
    fn session_authn(
        &self,
        flow: &mut Flow
    ) -> Result<AuthNResult<Self::Prin>, Self::Error>;
}

/// Trait for message authenticators.
///
/// These authenticators have access to session principals, but do
/// *not* have access to the underlying session.  They must make
/// authentication decisions *solely* based on a message that was
/// received.  They can, however, change the principal associated with
/// the message, and may use a wholly-different principal type.
///
/// This permits message authenticators to handle forwarded messages.
pub trait MsgAuthN<Msg, Wrapper> {
    /// Type of session principals.
    type SessionPrin: Clone + Display + Eq + Hash;
    /// Type of principals assigned to messages.
    type Prin: Display + Clone;
    /// Errors that can occur during message authentication.
    type Error: Display + ScopedError;

    /// Authenticate a message.
    ///
    /// This will return an [AuthNResult] containing a
    /// [Prin](SessionAuthN::Prin) in the case of success.
    ///
    /// This can produce a different principal from the session
    /// principal, as will be the case with forwarded messages.
    fn msg_authn(
        &self,
        session: &Self::SessionPrin,
        msg: Wrapper
    ) -> Result<AuthNResult<(Self::Prin, Msg)>, Self::Error>;
}

/// Common type for errors that can occur during session authentication.
#[derive(Debug)]
pub enum SessionAuthNError<Cred, AuthN> {
    /// Error obtaining credentials.
    Cred {
        /// Error that occurred obtaining credentials.
        err: Cred
    },
    /// Error during authentication process.
    AuthN {
        /// Error that occurred during authentication process.
        err: AuthN
    }
}

/// Type of results from authentication.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthNResult<Accept> {
    /// Authentication was successful.
    Accept(Accept),
    /// Authentication failed.
    Reject
}

#[derive(Clone, Default)]
pub struct PassthruSessionAuthN;

/// Simple message authenticator that associates the session principal
/// with each message.
pub struct PassthruMsgAuthN<Msg, Prin: Clone + Display> {
    prin: PhantomData<Prin>,
    msg: PhantomData<Msg>
}

/// An authenticator that consists solely of a static lookup table.
pub struct TestAuthN<Prin, Cred: Clone + Eq + Hash> {
    prins: HashMap<Cred, Prin>
}

impl<Cred, AuthN> ScopedError for SessionAuthNError<Cred, AuthN>
where
    Cred: ScopedError,
    AuthN: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionAuthNError::Cred { err } => err.scope(),
            SessionAuthNError::AuthN { err } => err.scope()
        }
    }
}

impl<Msg, Prin> Default for PassthruMsgAuthN<Msg, Prin>
where
    Prin: Clone + Display
{
    #[inline]
    fn default() -> Self {
        PassthruMsgAuthN {
            prin: PhantomData,
            msg: PhantomData
        }
    }
}

impl<Msg, Prin> Clone for PassthruMsgAuthN<Msg, Prin>
where
    Prin: Clone + Display
{
    #[inline]
    fn clone(&self) -> Self {
        PassthruMsgAuthN::default()
    }
}

unsafe impl<Msg, Prin> Send for PassthruMsgAuthN<Msg, Prin> where
    Prin: Clone + Display
{
}

unsafe impl<Msg, Prin> Sync for PassthruMsgAuthN<Msg, Prin> where
    Prin: Clone + Display
{
}

impl<Msg, Prin> MsgAuthN<Msg, Msg> for PassthruMsgAuthN<Msg, Prin>
where
    Prin: Clone + Display + Eq + Hash
{
    type Error = Infallible;
    type Prin = Prin;
    type SessionPrin = Prin;

    fn msg_authn(
        &self,
        session: &Self::SessionPrin,
        msg: Msg
    ) -> Result<AuthNResult<(Self::Prin, Msg)>, Self::Error> {
        Ok(AuthNResult::Accept((session.clone(), msg)))
    }
}

impl<Prin, Cred> TestAuthN<Prin, Cred>
where
    Cred: Clone + Eq + Hash
{
    #[inline]
    pub fn create<I>(parties: I) -> Self
    where
        I: Iterator<Item = (Cred, Prin)> {
        TestAuthN {
            prins: parties.collect()
        }
    }
}

impl<Flow> SessionAuthN<Flow> for PassthruSessionAuthN
where
    Flow: Credentials + Read + Write
{
    type Error = Infallible;
    type Prin = NullCred;

    #[inline]
    fn session_authn_nonblock(
        &self,
        _flow: &mut Flow
    ) -> Result<NonblockResult<AuthNResult<Self::Prin>, ()>, Self::Error> {
        Ok(NonblockResult::Success(AuthNResult::Accept(NullCred)))
    }

    fn session_authn(
        &self,
        _flow: &mut Flow
    ) -> Result<AuthNResult<Self::Prin>, Self::Error> {
        Ok(AuthNResult::Accept(NullCred))
    }
}

impl<Prin, Cred, Flow> SessionAuthN<Flow> for TestAuthN<Prin, Cred>
where
    Cred: Clone + Display + Eq + Hash,
    for<'a> Flow::Cred<'a>: TryInto<Cred>,
    Flow: Credentials + Read + Write,
    Flow::CredError: ScopedError,
    Prin: Clone + Display + Eq + Hash
{
    type Error = SessionAuthNError<Flow::CredError, Infallible>;
    type Prin = Prin;

    #[inline]
    fn session_authn_nonblock(
        &self,
        flow: &mut Flow
    ) -> Result<NonblockResult<AuthNResult<Self::Prin>, ()>, Self::Error> {
        Ok(NonblockResult::Success(self.session_authn(flow)?))
    }

    fn session_authn(
        &self,
        flow: &mut Flow
    ) -> Result<AuthNResult<Self::Prin>, Self::Error> {
        let cred = flow
            .creds()
            .map_err(|err| SessionAuthNError::Cred { err: err })?;

        match cred {
            Some(cred) => match cred.try_into() {
                Ok(cred) => {
                    trace!(target: "test-authn",
                           "harvested credentials from session: {}",
                           cred);

                    match self.prins.get(&cred) {
                        Some(prin) => Ok(AuthNResult::Accept(prin.clone())),
                        None => Ok(AuthNResult::Reject)
                    }
                }
                Err(_) => {
                    trace!(target: "test-authn",
                           "failed to convert harvested credentials");

                    Ok(AuthNResult::Reject)
                }
            },
            None => {
                trace!(target: "test-authn",
                       "no harvested credentials from session");

                Ok(AuthNResult::Reject)
            }
        }
    }
}

impl<Prin, Cred, Flow> SessionAuthN<Flow> for Arc<TestAuthN<Prin, Cred>>
where
    Cred: Clone + Display + Eq + Hash,
    for<'a> Flow::Cred<'a>: TryInto<Cred>,
    Flow: Credentials + Read + Write,
    Flow::CredError: ScopedError,
    Prin: Clone + Display + Eq + Hash
{
    type Error = SessionAuthNError<Flow::CredError, Infallible>;
    type Prin = Prin;

    #[inline]
    fn session_authn_nonblock(
        &self,
        flow: &mut Flow
    ) -> Result<NonblockResult<AuthNResult<Self::Prin>, ()>, Self::Error> {
        Ok(NonblockResult::Success(self.session_authn(flow)?))
    }

    fn session_authn(
        &self,
        flow: &mut Flow
    ) -> Result<AuthNResult<Self::Prin>, Self::Error> {
        self.as_ref().session_authn(flow)
    }
}

unsafe impl<Prin, Cred> Sync for TestAuthN<Prin, Cred> where
    Cred: Clone + Eq + Hash
{
}

impl<Cred, AuthN> Display for SessionAuthNError<Cred, AuthN>
where
    Cred: Display,
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionAuthNError::Cred { err } => err.fmt(f),
            SessionAuthNError::AuthN { err } => err.fmt(f)
        }
    }
}

#[test]
fn token() {}
