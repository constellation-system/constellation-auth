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

use constellation_common::codec::Decoder;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::nonblock::NonblockResult;
use log::trace;

use crate::config::TestAuthNConfig;
use crate::cred::Credentials;
use crate::cred::NullCred;

/// Trait for authenticated objects, produced by [SessionAuthN] or
/// [MsgAuthN] instances.
///
/// There is deliberately no way to create instances of this trait;
/// they should only be created by the authenticator, guaranteeing at
/// the type level that these have successfully gone through
/// authentication.
///
/// # Type Parameters
///
/// * `Prin`: Type of prinicpals.
/// * `T`: Type of authenticated objects.
pub trait AuthNed<Prin, T> {
    /// Get the principal for this `AuthNed` object.
    fn prin(&self) -> &Prin;

    /// Get a reference to the object that was authenticated.
    fn get(&self) -> &T;

    /// Get a mutable reference to the object that was authenticated.
    fn get_mut(&mut self) -> &mut T;

    /// Deconstruct this into the payload and principal.
    fn take(self) -> (T, Prin);
}

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
pub trait SessionAuthN<Stream>
where
    Stream: Credentials + Read + Write {
    /// Type of session prinicpals.
    type Prin: Clone + Display + Eq + Hash;
    /// Type of errors that can occur during authentication.
    type Error: Display + ScopedError;
    /// Type of authenticated flows produced by this authenticator.
    type AuthNSession: AuthNed<Self::Prin, Stream>;

    /// Attempt to perform session authentication without blocking.
    ///
    /// This will return an [AuthNResult] containing a
    /// [Prin](SessionAuthN::Prin) in the case of success.
    fn session_authn_nonblock(
        &self,
        flow: Stream
    ) -> Result<
        NonblockResult<AuthNResult<Self::AuthNSession, Stream>, Stream>,
        Self::Error
    >;

    /// Perform session authentication.
    ///
    /// This will return an [AuthNResult] containing a
    /// [Prin](SessionAuthN::Prin) in the case of success.
    fn session_authn(
        &self,
        flow: Stream
    ) -> Result<AuthNResult<Self::AuthNSession, Stream>, Self::Error>;
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
    /// Type of authenticated messages produced by this authenticator.
    type AuthNMsg: AuthNed<Self::Prin, Msg>;

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
    ) -> Result<AuthNResult<Self::AuthNMsg, ()>, Self::Error>;
}

/// Type trait for relationships between [Decoder]s, [SessionAuthN]s,
/// and [MsgAuthN]s.
///
/// This is used to avoid complex type constraints on types that use
/// [SessionAuthN]s to authenticate a session, which then supplies
/// messages of a particular type that are decoded by an [Decoder],
/// then subsequently authenticated (and possibly unwrapped) by a
/// [MsgAuthN].
///
/// # Type Parameters
///
/// * `Stream`: Type of streams used by the [SessionAuthN] to authenticate
///   sessions.
/// * `Msg`: Type of messages ultimately produced by this chain.
pub trait AuthNTypes<Stream, Msg>
where
    Stream: Credentials + Read + Write {
    /// Type of wrapper messages.
    type Wrapper;
    /// Type of [Decoder]s used to decode messages of type
    /// [Wrapper](AuthNTypes::Wrapper).
    type Decoder: Decoder<Self::Wrapper>;
    /// Type of session authenticators
    type SessionAuthN: SessionAuthN<Stream>;
    /// Type of message authenticators.
    type MsgAuthN: MsgAuthN<
        Msg,
        Self::Wrapper,
        SessionPrin = <Self::SessionAuthN as SessionAuthN<Stream>>::Prin
    >;
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
pub enum AuthNResult<Accept, Reject> {
    /// Authentication was successful.
    Accept(Accept),
    /// Authentication failed.
    Reject(Reject)
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

#[derive(Clone)]
pub struct TrivialAuthN<Cred: Clone + Eq + Hash> {
    cred: PhantomData<Cred>
}

pub struct NullAuthNed<T> {
    content: T
}

pub struct BasicAuthNed<Prin, T> {
    prin: Prin,
    content: T
}

#[derive(Debug)]
pub enum TestAuthNCreateError<Convert, Cred> {
    Convert { err: Convert },
    Duplicate { cred: Cred }
}

impl<Prin, T> AuthNed<Prin, T> for BasicAuthNed<Prin, T> {
    #[inline]
    fn prin(&self) -> &Prin {
        &self.prin
    }

    #[inline]
    fn get(&self) -> &T {
        &self.content
    }

    #[inline]
    fn get_mut(&mut self) -> &mut T {
        &mut self.content
    }

    #[inline]
    fn take(self) -> (T, Prin) {
        (self.content, self.prin)
    }
}

impl<T> AuthNed<NullCred, T> for NullAuthNed<T> {
    #[inline]
    fn prin(&self) -> &NullCred {
        &NullCred
    }

    #[inline]
    fn get(&self) -> &T {
        &self.content
    }

    #[inline]
    fn get_mut(&mut self) -> &mut T {
        &mut self.content
    }

    #[inline]
    fn take(self) -> (T, NullCred) {
        (self.content, NullCred)
    }
}

impl<Cred> Default for TrivialAuthN<Cred>
where
    Cred: Clone + Eq + Hash
{
    #[inline]
    fn default() -> Self {
        TrivialAuthN { cred: PhantomData }
    }
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
    type AuthNMsg = BasicAuthNed<Prin, Msg>;
    type Error = Infallible;
    type Prin = Prin;
    type SessionPrin = Prin;

    #[inline]
    fn msg_authn(
        &self,
        session: &Self::SessionPrin,
        msg: Msg
    ) -> Result<AuthNResult<Self::AuthNMsg, ()>, Self::Error> {
        Ok(AuthNResult::Accept(BasicAuthNed {
            prin: session.clone(),
            content: msg
        }))
    }
}

impl<Prin, Cred> TestAuthN<Prin, Cred>
where
    Prin: Clone + Eq + Hash,
    Cred: Clone + Eq + Hash
{
    #[inline]
    pub fn from_parties<I>(parties: I) -> Self
    where
        I: Iterator<Item = (Cred, Prin)> {
        TestAuthN {
            prins: parties.collect()
        }
    }

    pub fn create<CredConfig>(
        config: TestAuthNConfig<Prin, CredConfig>
    ) -> Result<Self, TestAuthNCreateError<CredConfig::Error, Cred>>
    where
        CredConfig: TryInto<Cred> {
        let mut prins = HashMap::new();

        for prin in config.into_iter() {
            let (prin, creds) = prin.take();

            for cred in creds.into_iter() {
                let cred = cred.try_into().map_err(|err| {
                    TestAuthNCreateError::Convert { err: err }
                })?;

                if prins.insert(cred.clone(), prin.clone()).is_some() {
                    return Err(TestAuthNCreateError::Duplicate { cred: cred });
                }
            }
        }

        Ok(TestAuthN { prins: prins })
    }
}

impl<Flow> SessionAuthN<Flow> for PassthruSessionAuthN
where
    Flow: Credentials + Read + Write
{
    type AuthNSession = NullAuthNed<Flow>;
    type Error = Infallible;
    type Prin = NullCred;

    #[inline]
    fn session_authn_nonblock(
        &self,
        flow: Flow
    ) -> Result<
        NonblockResult<AuthNResult<NullAuthNed<Flow>, Flow>, Flow>,
        Self::Error
    > {
        Ok(NonblockResult::Success(AuthNResult::Accept(NullAuthNed {
            content: flow
        })))
    }

    #[inline]
    fn session_authn(
        &self,
        flow: Flow
    ) -> Result<AuthNResult<NullAuthNed<Flow>, Flow>, Self::Error> {
        Ok(AuthNResult::Accept(NullAuthNed { content: flow }))
    }
}

impl<Flow, Cred> SessionAuthN<Flow> for TrivialAuthN<Cred>
where
    Cred: Clone + Display + Eq + Hash,
    Flow::Cred: TryInto<Cred>,
    Flow: Credentials + Read + Write,
    Flow::CredError: ScopedError
{
    type AuthNSession = BasicAuthNed<Self::Prin, Flow>;
    type Error = SessionAuthNError<Flow::CredError, Infallible>;
    type Prin = Cred;

    #[inline]
    fn session_authn_nonblock(
        &self,
        flow: Flow
    ) -> Result<
        NonblockResult<AuthNResult<BasicAuthNed<Self::Prin, Flow>, Flow>, Flow>,
        Self::Error
    > {
        Ok(NonblockResult::Success(self.session_authn(flow)?))
    }

    fn session_authn(
        &self,
        flow: Flow
    ) -> Result<AuthNResult<BasicAuthNed<Self::Prin, Flow>, Flow>, Self::Error>
    {
        let cred = flow
            .creds()
            .map_err(|err| SessionAuthNError::Cred { err: err })?;

        match cred {
            Some(cred) => match cred.try_into() {
                Ok(cred) => {
                    trace!(target: "test-authn",
                           "harvested credentials from session: {}",
                           cred);

                    Ok(AuthNResult::Accept(BasicAuthNed {
                        content: flow,
                        prin: cred
                    }))
                }
                Err(_) => {
                    trace!(target: "test-authn",
                           "failed to convert harvested credentials");

                    Ok(AuthNResult::Reject(flow))
                }
            },
            None => {
                trace!(target: "test-authn",
                       "no harvested credentials from session");

                Ok(AuthNResult::Reject(flow))
            }
        }
    }
}

impl<Prin, Cred, Flow> SessionAuthN<Flow> for TestAuthN<Prin, Cred>
where
    Cred: Clone + Display + Eq + Hash,
    Flow::Cred: TryInto<Cred>,
    Flow: Credentials + Read + Write,
    Flow::CredError: ScopedError,
    Prin: Clone + Display + Eq + Hash
{
    type AuthNSession = BasicAuthNed<Self::Prin, Flow>;
    type Error = SessionAuthNError<Flow::CredError, Infallible>;
    type Prin = Prin;

    #[inline]
    fn session_authn_nonblock(
        &self,
        flow: Flow
    ) -> Result<
        NonblockResult<AuthNResult<BasicAuthNed<Self::Prin, Flow>, Flow>, Flow>,
        Self::Error
    > {
        Ok(NonblockResult::Success(self.session_authn(flow)?))
    }

    fn session_authn(
        &self,
        flow: Flow
    ) -> Result<AuthNResult<BasicAuthNed<Self::Prin, Flow>, Flow>, Self::Error>
    {
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
                        Some(prin) => Ok(AuthNResult::Accept(BasicAuthNed {
                            content: flow,
                            prin: prin.clone()
                        })),
                        None => Ok(AuthNResult::Reject(flow))
                    }
                }
                Err(_) => {
                    trace!(target: "test-authn",
                           "failed to convert harvested credentials");

                    Ok(AuthNResult::Reject(flow))
                }
            },
            None => {
                trace!(target: "test-authn",
                       "no harvested credentials from session");

                Ok(AuthNResult::Reject(flow))
            }
        }
    }
}

impl<Prin, Cred, Flow> SessionAuthN<Flow> for Arc<TestAuthN<Prin, Cred>>
where
    Cred: Clone + Display + Eq + Hash,
    Flow::Cred: TryInto<Cred>,
    Flow: Credentials + Read + Write,
    Flow::CredError: ScopedError,
    Prin: Clone + Display + Eq + Hash
{
    type AuthNSession = BasicAuthNed<Self::Prin, Flow>;
    type Error = SessionAuthNError<Flow::CredError, Infallible>;
    type Prin = Prin;

    #[inline]
    fn session_authn_nonblock(
        &self,
        flow: Flow
    ) -> Result<
        NonblockResult<AuthNResult<BasicAuthNed<Self::Prin, Flow>, Flow>, Flow>,
        Self::Error
    > {
        Ok(NonblockResult::Success(self.session_authn(flow)?))
    }

    fn session_authn(
        &self,
        flow: Flow
    ) -> Result<AuthNResult<BasicAuthNed<Self::Prin, Flow>, Flow>, Self::Error>
    {
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

impl<Prin, Cred> Display for TestAuthNCreateError<Prin, Cred>
where
    Prin: Display,
    Cred: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            TestAuthNCreateError::Convert { err } => err.fmt(f),
            TestAuthNCreateError::Duplicate { cred } => {
                write!(f, "duplicate credential {}", cred)
            }
        }
    }
}

#[test]
fn token() {}
