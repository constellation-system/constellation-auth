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

use std::cell::Ref;
use std::cell::RefCell;
use std::cell::RefMut;
use std::collections::HashMap;
use std::convert::Infallible;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::rc::Rc;

use constellation_common::error::ScopedError;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use log::trace;

use crate::authn::AuthNMsgRecv;
use crate::authn::AuthNResult;
use crate::authn::AuthNed;
use crate::authn::BasicAuthNed;
use crate::authn::NullCred;
use crate::authn::SessionAuthN;
use crate::authn::SessionAuthNError;
use crate::config::TestAuthNConfig;
use crate::cred::Credentials;

/// An authenticator that consists solely of a static lookup table.
pub struct TestAuthN<Prin, Cred: Clone + Eq + Hash, Stream> {
    stream: PhantomData<Stream>,
    prins: HashMap<Cred, Prin>
}

pub struct TestAuthNSessionNegotiation<Stream> {
    stream: Stream
}

#[derive(Clone)]
pub struct TestAuthNMsgRecv<Msg> {
    msgs: Rc<RefCell<Vec<Msg>>>
}

#[derive(Debug)]
pub enum TestAuthNCreateError<Convert, Cred> {
    Convert { err: Convert },
    Duplicate { cred: Cred }
}

impl<Msg> Default for TestAuthNMsgRecv<Msg> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Msg> TestAuthNMsgRecv<Msg> {
    #[inline]
    pub fn new() -> Self {
        TestAuthNMsgRecv {
            msgs: Rc::new(RefCell::new(Vec::new()))
        }
    }

    #[inline]
    pub fn with_capacity(size: usize) -> Self {
        TestAuthNMsgRecv {
            msgs: Rc::new(RefCell::new(Vec::with_capacity(size)))
        }
    }

    /// Get the message buffer.
    #[inline]
    pub fn msgs(&self) -> Ref<'_, Vec<Msg>> {
        self.msgs.try_borrow().expect("try_borrow failed")
    }

    /// Get the message buffer.
    #[inline]
    pub fn msgs_mut(&mut self) -> RefMut<'_, Vec<Msg>> {
        self.msgs.try_borrow_mut().expect("try_borrow failed")
    }
}

impl<Msg> AuthNMsgRecv<NullCred, Msg, BasicAuthNed<NullCred, Msg>>
    for TestAuthNMsgRecv<Msg>
{
    type RecvError = Infallible;

    #[inline]
    fn recv_auth_msg(
        &mut self,
        msg: BasicAuthNed<NullCred, Msg>
    ) -> Result<(), Self::RecvError> {
        let (_, msg) = msg.take();

        self.msgs
            .try_borrow_mut()
            .expect("try_borrow failed")
            .push(msg);

        Ok(())
    }
}

impl<Prin, Cred, Stream> TestAuthN<Prin, Cred, Stream>
where
    Prin: Clone + Eq + Hash,
    Cred: Clone + Eq + Hash
{
    #[inline]
    pub fn from_parties<I>(parties: I) -> Self
    where
        I: Iterator<Item = (Cred, Prin)> {
        TestAuthN {
            stream: PhantomData,
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

        Ok(TestAuthN {
            stream: PhantomData,
            prins: prins
        })
    }
}

impl<Stream, Cred, Prin>
    NegotiatorStart<AuthNResult<BasicAuthNed<Prin, Stream>, Stream>, Stream>
    for TestAuthN<Prin, Cred, Stream>
where
    Cred: Clone + Display + Eq + Hash,
    Stream::Cred: TryInto<Cred>,
    Stream: Credentials + Read + Write,
    Stream::CredError: ScopedError,
    Prin: Clone + Display + Eq + Hash
{
    type Param = ();
    type StartError = Infallible;

    #[inline]
    fn start(
        &self,
        _param: &(),
        stream: Stream
    ) -> Result<TestAuthNSessionNegotiation<Stream>, Self::StartError> {
        Ok(TestAuthNSessionNegotiation { stream: stream })
    }
}

impl<Stream, Cred, Prin>
    Negotiator<AuthNResult<BasicAuthNed<Prin, Stream>, Stream>>
    for TestAuthN<Prin, Cred, Stream>
where
    Cred: Clone + Display + Eq + Hash,
    Stream::Cred: TryInto<Cred>,
    Stream: Credentials + Read + Write,
    Stream::CredError: ScopedError,
    Prin: Clone + Display + Eq + Hash
{
    type NegotiateError = SessionAuthNError<Stream::CredError, Infallible>;
    type Pending = Infallible;
    type State = TestAuthNSessionNegotiation<Stream>;

    /// Perform negotiations.
    #[inline]
    fn negotiate(
        &self,
        state: TestAuthNSessionNegotiation<Stream>
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<Prin, Stream>, Stream>,
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
                Ok(cred) => {
                    trace!(target: "test-authn",
                           "harvested credentials from session: {}",
                           cred);

                    match self.prins.get(&cred) {
                        Some(prin) => Ok(NegotiatorResult::Complete(
                            AuthNResult::Accept(BasicAuthNed {
                                content: state.stream,
                                prin: prin.clone()
                            })
                        )),
                        None => Ok(NegotiatorResult::Complete(
                            AuthNResult::Reject(state.stream)
                        ))
                    }
                }
                Err(_) => {
                    trace!(target: "test-authn",
                           "failed to convert harvested credentials");

                    let stream = state.stream;

                    Ok(NegotiatorResult::Complete(AuthNResult::Reject(stream)))
                }
            },
            None => {
                trace!(target: "test-authn",
                       "no harvested credentials from session");

                let stream = state.stream;

                Ok(NegotiatorResult::Complete(AuthNResult::Reject(stream)))
            }
        }
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<
        NegotiatorResult<
            AuthNResult<BasicAuthNed<Prin, Stream>, Stream>,
            Self::Pending
        >,
        Self::NegotiateError
    > {
        panic!("This should never be called!")
    }
}

impl<Stream, Prin, Cred> SessionAuthN<Stream> for TestAuthN<Prin, Cred, Stream>
where
    Stream::Cred: TryInto<Cred>,
    Stream: Credentials + Read + Write,
    Stream::CredError: ScopedError,
    Cred: Clone + Display + Eq + Hash,
    Prin: Clone + Debug + Display + Eq + Hash
{
    type AuthNSession = BasicAuthNed<Self::Prin, Stream>;
    type Prin = Prin;
}

unsafe impl<Prin, Cred, Stream> Sync for TestAuthN<Prin, Cred, Stream> where
    Cred: Clone + Eq + Hash
{
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
