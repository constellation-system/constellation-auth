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

//! Authentication functionality.
//!
//! This module provides traits for both session and message
//! authentication, along with some basic implementations.
//!
//! # Session Authentication
//!
//! Session authentication is implemented through the [`SessionAuthN`]
//! trait, which is in turn based on the [`Negotiator`] trait
//! hierarchy.  Session authenticators have access to a raw session,
//! and can perform a sub-protocol as part of authentication.
//!
//! # Message Authentication
//!
//! Message authentication in implemented through the [`MsgAuthN`]
//! trait.  Message authentication must make authentication decisions
//! based on a session principal, and on an individual message;
//! however, it can transform the message (e.g. unwrapping a CMS
//! envelope).
//!
//! # Type-Level Protection
//!
//! The API for authentication is designed to provide *type-level*
//! protection against failure to authenticate sessions and messages.
//! Both the session and message authentication trait APIs produce
//! associated types implementing [`AuthNed`] and its sub-traits
//! ([`SessionAuthN::AuthNSession`], and [`MsgAuthN::AuthNMsg`]).  The
//! [`AuthNed`] trait hierarchy in turn provides no functionality for
//! creating instances.  This means the *only* way of obtaining an
//! instance of the associated type is through the authenticator
//! implementation itself.
//!
//! Then, if consumer APIs use the aforementioned associated types,
//! this guarantees that those objects have been authenticated.
use std::convert::Infallible;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;

use constellation_common::codec::Decoder;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::RecoverableError;
use constellation_common::error::ScopedError;
use constellation_common::error::WithMutexPoison;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use log::trace;

use crate::cred::Credentials;
use crate::cred::NullCred;

pub mod basic;
pub mod test;

/// Trait for authenticated objects, produced by [`SessionAuthN`] or
/// [`MsgAuthN`] instances.
///
/// This wraps an inner object type, providing a way of obtaining the
/// principal against which it was authenticated.
///
/// There is deliberately no way to create instances of this trait
/// specified by the trait itself; instances should only be created by
/// the authenticator, guaranteeing at the *type level* that these
/// have successfully gone through authentication.
///
/// # Type Parameters
///
/// - `Prin`: Type of prinicpals.
pub trait AuthNed<Prin> {
    /// Get the principal for this `AuthNed` object.
    fn prin(&self) -> &Prin;
}

/// Trait for decomposing of authenticated objects back into their
/// components.
///
/// Once decomposed, an authenticated object generally *cannot* be
/// reconstituted if only this trait and [`AuthNed`] are being used.
/// This is generally only used for session shutdown procedures.
///
/// # Type Parameters
///
/// - `Prin`: Type of prinicpals.
///
/// - `T`: Type of inner objects.
pub trait AuthNedDestruct<Prin, T>: AuthNed<Prin> {
    /// Deconstruct this into the payload and principal.
    fn take(self) -> (Prin, T);
}

/// Trait for applying a transformation to the inner type of an
/// authenticated object.
///
/// This permits the inner object to be transformed without
/// deconstructing the authenticated object (and thus having no way to
/// reconstitute it).  There is deliberately no way to apply a
/// transformation to the principal.
///
/// # Type Parameters
///
/// - `Prin`: Type of prinicpals.
///
/// - `T`: Type of inner objects.
///
/// - `S`: Type of transformed inner objects.
///
/// - `Other`: Type of transformed [`AuthNed`] instance.
pub trait AuthNedMap<Prin, T, S, Other>:
    AuthNedDestruct<Prin, T> + Sized
where
    Other: AuthNedDestruct<Prin, S> {
    /// Apply a transformation to the inner object of an authenticated
    /// object.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Type of transformation.
    ///
    /// # Parameters
    ///
    /// - `f`: The transformation to apply.
    fn map<F>(
        self,
        f: F
    ) -> Other
    where
        F: FnOnce(T) -> S;
}

/// Receiver for authenticated messages.
///
/// # Type Parameters
///
/// - `Prin`: Type of principals.
///
/// - `AuthNMsg`: Type of authenticated messages (must be an [`AuthNed`]
///   instance).
pub trait AuthNMsgRecv<Prin, AuthNMsg>
where
    AuthNMsg: AuthNed<Prin> {
    /// Errors that can occur reporting messages.
    type RecvError: Debug + Display + ScopedError;

    /// Receive an authenticated message.
    ///
    /// # Parameters
    ///
    /// - `msg`: Message to be received.
    fn recv_auth_msg(
        &mut self,
        msg: AuthNMsg
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
///
/// # Usage
///
/// The actual authentication functionality for this trait is handled
/// through the [`Negotiator`] and [`NegotiatorStart`] sub-traits.
/// The [`NegotiatorStart::start`] function is used to start
/// negotiations, which are then run using [`Negotiator::negotiate`]
/// until they produce an [`AuthNResult`] indicating acceptance or
/// rejection.
///
/// The functions defined in this trait are for recovering the session
/// from an error, so it can be shut down properly.
///
/// # Type Parameters
///
/// - `Session`: Type of underlying raw sessions.
pub trait SessionAuthN<Session>:
    Negotiator<AuthNResult<Self::AuthNSession, Session>>
    + NegotiatorStart<AuthNResult<Self::AuthNSession, Session>, Session>
where
    Session: Read + Write {
    /// Type of session prinicpals.
    type Prin: Clone + Debug + Display + Eq + Hash;
    /// Type of authenticated flows produced by this authenticator.
    type AuthNSession: AuthNed<Self::Prin>;

    /// Try to recover the underlying session from a negotiation error.
    ///
    /// Default behavior is to fail.
    ///
    /// # Parameters
    ///
    /// - `err`: The error from which to recover the underying session.
    #[inline]
    fn err_stream(
        &self,
        _err: Self::NegotiateError
    ) -> Option<Session> {
        None
    }

    /// Try to recover the underlying session from a negotiation error.
    ///
    /// Default behavior is to fail.
    ///
    /// # Parameters
    ///
    /// - `err`: The error from which to recover the underying session.
    #[inline]
    fn start_err_stream(
        &self,
        _err: Self::StartError
    ) -> Option<Session> {
        None
    }
}

/// Trait for message authenticators.
///
/// These authenticators have access to session principals, but do
/// *not* have access to the underlying session.  They must make
/// authentication decisions *solely* based on a message that was
/// received.  They can, however, change the principal associated with
/// the message, and may use a wholly-different principal type.
///
/// These authenticators may also change the type of the message, for
/// example, uwnrapping it from an envelope (e.g. CMS messages).
///
/// This permits message authenticators to handle forwarded messages.
///
/// # Type Parameters
///
/// - `Msg`: The type of message payloads resulting from message authentication.
///
/// - `Wrapper`: The type of input messages to message authentication. This may
///   be an envelope type (e.g. CMS).
pub trait MsgAuthN<Msg, Wrapper> {
    /// Type of session principals.
    type SessionPrin: Clone + Debug + Display + Eq + Hash;
    /// Type of principals assigned to messages.
    type Prin: Debug + Display + Clone;
    /// Errors that can occur during message authentication.
    type Error: Debug + Display + ScopedError;
    /// Type of authenticated messages produced by this authenticator.
    type AuthNMsg: AuthNedDestruct<Self::Prin, Msg>;

    /// Authenticate a message.
    ///
    /// This will return an [`AuthNResult`] containing a
    /// [`Prin`](SessionAuthN::Prin) in the case of success.
    ///
    /// This can produce a different principal from the session
    /// principal, as will be the case with forwarded messages.
    ///
    /// # Parameters
    ///
    /// - `session_prin`: The session principal.
    ///
    /// - `msg`: The input message to be authenticated.
    fn msg_authn(
        &self,
        session_prin: &Self::SessionPrin,
        msg: Wrapper
    ) -> Result<AuthNResult<Self::AuthNMsg, ()>, Self::Error>;
}

/// Type trait for relationships between [`Decoder`]s and [`MsgAuthN`]s.
///
/// This is used to avoid complex type constraints on types that are
/// decoded by an [`Decoder`], then subsequently authenticated (and
/// possibly unwrapped) by a [`MsgAuthN`].
///
/// # Type Parameters
///
/// - `Msg`: Type of messages ultimately produced by this chain.
pub trait MsgAuthNTypes<Msg> {
    /// Type of wrapper messages.
    type Wrapper;
    /// Type of principals assigned to messages.
    type Prin: Debug + Display + Clone;
    /// Type of session principals.
    type SessionPrin: Clone + Debug + Display + Eq + Hash;
    /// Type of configuration objects for the
    /// [`Decoder`](MsgAuthNTypes::Decoder);
    type DecoderConfig: Default;
    /// Type of errors that can occur decoding with the
    /// [`Decoder`](MsgAuthNTypes::Decoder);
    type DecodeError: Debug + Display;
    /// Type of [`Decoder`]s used to decode messages of type
    /// [`Wrapper`](MsgAuthNTypes::Wrapper).
    type Decoder: Create<Config = Self::DecoderConfig>
        + Decoder<Self::Wrapper, DecodeError = Self::DecodeError>;
    /// Type of authentication errors that can occur with
    /// [`MsgAuthN`](MsgAuthNTypes::MsgAuthN).
    type AuthNError: Debug + Display;
    /// Type of message authenticators.
    type MsgAuthN: MsgAuthN<
        Msg,
        Self::Wrapper,
        SessionPrin = Self::SessionPrin,
        Prin = Self::Prin,
        Error = Self::AuthNError
    >;
}

/// Type trait for relationships between [`Decoder`]s, [`SessionAuthN`]s,
/// and [`MsgAuthN`]s.
///
/// This is used to avoid complex type constraints on types that use
/// [`SessionAuthN`]s to authenticate a session, which then supplies
/// messages of a particular type that are decoded by an [`Decoder`],
/// then subsequently authenticated (and possibly unwrapped) by a
/// [`MsgAuthN`].
///
/// # Type Parameters
///
/// - `Session`: Type of streams used by the [`SessionAuthN`] to authenticate
///   sessions.
///
/// - `Msg`: Type of messages ultimately produced by this chain.
pub trait AuthNTypes<Session, Msg>
where
    Session: Credentials + Read + Write {
    /// Type of session authenticators.
    type SessionAuthN: SessionAuthN<
        Session,
        Prin = <Self::MsgAuthNTypes as MsgAuthNTypes<Msg>>::SessionPrin
    >;
    /// Message authenticator type trait.
    type MsgAuthNTypes: MsgAuthNTypes<Msg>;
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
///
/// This indicates either acceptance or rejection of authentication.
///
/// # Type Parameters
///
/// - `Accept`: Type produced upon acceptance.
///
/// - `Reject`: Type produced upon rejection.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthNResult<Accept, Reject> {
    /// Authentication was successful.
    Accept(Accept),
    /// Authentication failed.
    Reject(Reject)
}

// XXX This should be converted to an alias for a general trivial
// [`Negotiator`] instance.

/// Trivial session authenticator.
///
/// This automatically passes every session, producing [`NullCred`] as
/// its session principl.
#[derive(Clone)]
pub struct PassthruSessionAuthN<Session> {
    stream: PhantomData<Session>
}

/// Type of negotiation for [`PassthruSessionAuthN`].
pub struct PassthruSessionNegotiation<Session> {
    stream: Session
}

/// Simple message authenticator that passes every message with the
/// session principal.
///
/// *This is a placeholder, and will eventually be relegated to
/// testing.*
pub struct PassthruMsgAuthN<Msg, Prin: Clone + Display> {
    prin: PhantomData<Prin>,
    msg: PhantomData<Msg>
}

pub struct TrivialSessionNegotiation<Session> {
    stream: Session
}

#[derive(Clone)]
pub struct TrivialAuthN<Cred: Clone + Eq + Hash, Session> {
    stream: PhantomData<Session>,
    cred: PhantomData<Cred>
}

/// A simple wrapper for authenticated objects.
///
/// This is usable as an [`AuthNed`] instance for nearly all
/// [`SessionAuthN`] and [`MsgAuthN`] instances' authenticated types.
/// However, this type should *never* be directly referenced outside
/// of an instance for these traits.
///
/// The fact that [`AuthNed`] and its subtraits provide no means of
/// creating an [`AuthNed`] instance, and the fact that authenticated
/// objects from [`SessionAuthN`] and [`MsgAuthN`] are associated
/// types of those traits provides a strong type-level protection
/// against failing to authenticate an object prior to using it.
/// Directly referencing `BasicAuthNed` risks bypassing this
/// type-level protection.
///
/// # Type Parameters
///
/// - `Prin`: Type of prinicpals.
///
/// - `T`: Type of inner objects.
#[derive(Clone)]
pub struct BasicAuthNed<Prin, T> {
    /// The principal.
    prin: Prin,
    /// The inner object.
    content: T
}

impl<Prin, AuthNMsg, T> AuthNMsgRecv<Prin, AuthNMsg> for Arc<Mutex<T>>
where
    T: AuthNMsgRecv<Prin, AuthNMsg>,
    AuthNMsg: AuthNed<Prin>
{
    type RecvError = WithMutexPoison<T::RecvError>;

    fn recv_auth_msg(
        &mut self,
        msg: AuthNMsg
    ) -> Result<(), Self::RecvError> {
        self.lock()
            .map_err(|_| WithMutexPoison::MutexPoison)?
            .recv_auth_msg(msg)
            .map_err(|err| WithMutexPoison::Inner { err: err })
    }
}

impl<Accept, Reject> AuthNResult<Accept, Reject> {
    /// Apply a transformation to the acceptance of an `AuthNResult`.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Type of the transformation function.
    ///
    /// - `T`: The result type of the transformation
    ///
    /// # Parameters
    ///
    /// - `f`: The transformation to apply.
    pub fn map<F, T>(
        self,
        f: F
    ) -> AuthNResult<T, Reject>
    where
        F: FnOnce(Accept) -> T {
        match self {
            AuthNResult::Accept(val) => AuthNResult::Accept(f(val)),
            AuthNResult::Reject(val) => AuthNResult::Reject(val)
        }
    }

    /// Apply a transformation to the acceptance of an `AuthNResult`.
    ///
    /// This variant permits the transformation to fail with an error.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Type of the transformation function.
    ///
    /// - `T`: The result type of the transformation
    ///
    /// - `E`: Type of errors that can occur.
    ///
    /// # Parameters
    ///
    /// - `f`: The transformation to apply.
    pub fn map_ok<F, T, E>(
        self,
        f: F
    ) -> Result<AuthNResult<T, Reject>, E>
    where
        F: FnOnce(Accept) -> Result<T, E> {
        match self {
            AuthNResult::Accept(val) => Ok(AuthNResult::Accept(f(val)?)),
            AuthNResult::Reject(val) => Ok(AuthNResult::Reject(val))
        }
    }
}

impl<Prin, T> BasicAuthNed<Prin, T> {
    /// Create a `BasicAuthNed` from its components.
    ///
    /// # Warning
    ///
    /// Do not *ever* use this function outside a [`SessionAuthN`] or
    /// [`MsgAuthN`] trait implementation.  See the main documentation
    /// of [`BasicAuthNed`] for more details.
    ///
    /// # Parameters
    ///
    /// - `prin`: The principal.
    ///
    /// - `content`: The inner object
    #[inline]
    pub(crate) fn new(
        prin: Prin,
        content: T
    ) -> Self {
        BasicAuthNed {
            prin: prin,
            content: content
        }
    }

    /// Get a reference to the inner object.
    #[inline]
    pub fn get(&self) -> &T {
        &self.content
    }

    /// Get a mutable reference to the inner object.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.content
    }
}

impl<Prin, T> AuthNed<Prin> for BasicAuthNed<Prin, T> {
    #[inline]
    fn prin(&self) -> &Prin {
        &self.prin
    }
}

impl<Prin, T> AuthNedDestruct<Prin, T> for BasicAuthNed<Prin, T> {
    #[inline]
    fn take(self) -> (Prin, T) {
        (self.prin, self.content)
    }
}

impl<Prin, T, S> AuthNedMap<Prin, T, S, BasicAuthNed<Prin, S>>
    for BasicAuthNed<Prin, T>
{
    fn map<F>(
        self,
        f: F
    ) -> BasicAuthNed<Prin, S>
    where
        F: FnOnce(T) -> S {
        let BasicAuthNed { prin, content } = self;
        let content = f(content);

        BasicAuthNed { prin, content }
    }
}

impl<Prin, T> Session for BasicAuthNed<Prin, T>
where
    T: Session
{
    type LocalAddr = T::LocalAddr;
    type PeerAddr = T::PeerAddr;

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, std::io::Error> {
        self.content.peer_addr()
    }

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, std::io::Error> {
        self.content.local_addr()
    }
}

impl<Prin, T> Read for BasicAuthNed<Prin, T>
where
    T: Read
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, std::io::Error> {
        self.content.read(buf)
    }

    #[inline]
    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, std::io::Error> {
        self.content.read_vectored(buf)
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, std::io::Error> {
        self.content.read_to_end(buf)
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, std::io::Error> {
        self.content.read_to_string(buf)
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), std::io::Error> {
        self.content.read_exact(buf)
    }
}

impl<Prin, T> Write for BasicAuthNed<Prin, T>
where
    T: Write
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, std::io::Error> {
        self.content.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.content.flush()
    }

    #[inline]
    fn write_vectored(
        &mut self,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, std::io::Error> {
        self.content.write_vectored(buf)
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), std::io::Error> {
        self.content.write_all(buf)
    }
}

unsafe impl<Cred, Session> Send for TrivialAuthN<Cred, Session> where
    Cred: Clone + Eq + Hash
{
}

unsafe impl<Cred, Session> Sync for TrivialAuthN<Cred, Session> where
    Cred: Clone + Eq + Hash
{
}

impl<Cred, Session, Ctx> CreateWithParam<Ctx> for TrivialAuthN<Cred, Session>
where
    Cred: Clone + Eq + Hash
{
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(
        _config: Self::Config,
        _param: Ctx
    ) -> Result<Self, Self::CreateError> {
        Ok(TrivialAuthN::default())
    }
}

impl<Cred, Session> Default for TrivialAuthN<Cred, Session>
where
    Cred: Clone + Eq + Hash
{
    #[inline]
    fn default() -> Self {
        TrivialAuthN {
            stream: PhantomData,
            cred: PhantomData
        }
    }
}

impl<Cred, AuthN> RecoverableError for SessionAuthNError<Cred, AuthN>
where
    AuthN: Debug + Display + ScopedError,
    Cred: Debug + Display + ScopedError
{
    type Completable = Infallible;
    type Permanent = SessionAuthNError<Cred, AuthN>;

    fn split(self) -> (Option<Self::Completable>, Option<Self::Permanent>) {
        (None, Some(self))
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

impl<Msg, Prin> Create for PassthruMsgAuthN<Msg, Prin>
where
    Prin: Clone + Display
{
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: Self::Config) -> Result<Self, Self::CreateError> {
        Ok(Self::default())
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
    Prin: Clone + Debug + Display + Eq + Hash
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

impl<Session> Default for PassthruSessionAuthN<Session>
where
    Session: Credentials + Read + Write
{
    #[inline]
    fn default() -> Self {
        PassthruSessionAuthN {
            stream: PhantomData
        }
    }
}

impl<Session> Negotiator<AuthNResult<BasicAuthNed<NullCred, Session>, Session>>
    for PassthruSessionAuthN<Session>
where
    Session: Credentials + Read + Write
{
    type NegotiateError = Infallible;
    type Pending = Infallible;
    type State = PassthruSessionNegotiation<Session>;

    /// Perform negotiations.
    #[inline]
    fn negotiate(
        &self,
        state: PassthruSessionNegotiation<Session>
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<NullCred, Session>, Session>,
            Self::Pending
        >,
        Self::NegotiateError
    > {
        Ok(NegotiatorResult::Complete(AuthNResult::Accept(
            BasicAuthNed {
                content: state.stream,
                prin: NullCred
            }
        )))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<NullCred, Session>, Session>,
            Self::Pending
        >,
        Self::NegotiateError
    > {
        panic!("This should never be called!")
    }
}

impl<Session>
    NegotiatorStart<
        AuthNResult<BasicAuthNed<NullCred, Session>, Session>,
        Session
    > for PassthruSessionAuthN<Session>
where
    Session: Credentials + Read + Write
{
    type Param = ();
    type StartError = Infallible;

    #[inline]
    fn start(
        &self,
        _param: &(),
        stream: Session
    ) -> Result<PassthruSessionNegotiation<Session>, Self::StartError> {
        Ok(PassthruSessionNegotiation { stream: stream })
    }
}

impl<Flow> SessionAuthN<Flow> for PassthruSessionAuthN<Flow>
where
    Flow: Credentials + Read + Write
{
    type AuthNSession = BasicAuthNed<NullCred, Flow>;
    type Prin = NullCred;
}

impl<Session, Prin>
    NegotiatorStart<AuthNResult<BasicAuthNed<Prin, Session>, Session>, Session>
    for TrivialAuthN<Prin, Session>
where
    Prin: Clone + Default + Display + Eq + Hash,
    Session::Cred: TryInto<Prin>,
    Session: Credentials + Read + Write,
    Session::CredError: ScopedError
{
    type Param = ();
    type StartError = Infallible;

    #[inline]
    fn start(
        &self,
        _param: &(),
        stream: Session
    ) -> Result<TrivialSessionNegotiation<Session>, Self::StartError> {
        Ok(TrivialSessionNegotiation { stream: stream })
    }
}

impl<Session, Prin>
    Negotiator<AuthNResult<BasicAuthNed<Prin, Session>, Session>>
    for TrivialAuthN<Prin, Session>
where
    Prin: Clone + Default + Display + Eq + Hash,
    Session::Cred: TryInto<Prin>,
    Session: Credentials + Read + Write,
    Session::CredError: ScopedError
{
    type NegotiateError = SessionAuthNError<Session::CredError, Infallible>;
    type Pending = Infallible;
    type State = TrivialSessionNegotiation<Session>;

    /// Perform negotiations.
    #[inline]
    fn negotiate(
        &self,
        state: TrivialSessionNegotiation<Session>
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<Prin, Session>, Session>,
            Self::Pending
        >,
        Self::NegotiateError
    > {
        let cred = state
            .stream
            .creds()
            .map_err(|err| SessionAuthNError::Cred { err: err })?;

        match cred {
            Some(cred) => match cred.try_into() {
                Ok(prin) => {
                    trace!(target: "trivial-authn",
                           "harvested credentials from session: {}",
                           prin);

                    Ok(NegotiatorResult::Complete(AuthNResult::Accept(
                        BasicAuthNed {
                            content: state.stream,
                            prin: prin
                        }
                    )))
                }
                Err(_) => {
                    trace!(target: "test-authn",
                           "failed to convert harvested credentials");

                    let stream = state.stream;

                    Ok(NegotiatorResult::Complete(AuthNResult::Reject(stream)))
                }
            },
            None => {
                trace!(target: "trivial-authn",
                       "no harvested credentials from session");

                Ok(NegotiatorResult::Complete(AuthNResult::Accept(
                    BasicAuthNed {
                        content: state.stream,
                        prin: Prin::default()
                    }
                )))
            }
        }
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<Prin, Session>, Session>,
            Self::Pending
        >,
        Self::NegotiateError
    > {
        panic!("This should never be called!")
    }
}

impl<Flow, Cred> SessionAuthN<Flow> for TrivialAuthN<Cred, Flow>
where
    Cred: Clone + Debug + Default + Display + Eq + Hash,
    Flow::Cred: TryInto<Cred>,
    Flow: Credentials + Read + Write,
    Flow::CredError: ScopedError
{
    type AuthNSession = BasicAuthNed<Self::Prin, Flow>;
    type Prin = Cred;
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
