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

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
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
    principal: Prin,
    credentials: Vec<Cred>
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
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

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "unsafe-basic-cred")]
#[serde(untagged)]
pub enum UnsafeBasicCredConfig {
    IP {
        #[serde(rename = "ip")]
        unsafe_ip: SocketAddr
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
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
    principal: Prin,
    credentials: Cred
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct HostAuthNUnsafeConfig {
    allow_unsafe_ip_creds: bool
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "basic-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct BasicAuthNConfig<Prin> {
    rules: Vec<BasicAuthNPrinConfig<Prin, BasicCredConfig>>,
    #[serde(default)]
    #[serde(rename = "unsafe")]
    unsafe_opts: HostAuthNUnsafeConfig
}

pub type TestAuthNConfig<Prin, Cred> = Vec<TestAuthNPrinConfig<Prin, Cred>>;

impl Default for HostAuthNUnsafeConfig {
    #[inline]
    fn default() -> Self {
        HostAuthNUnsafeConfig {
            allow_unsafe_ip_creds: false
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
        principal: Prin,
        creds: Cred
    ) -> Self {
        BasicAuthNPrinConfig {
            principal: principal,
            credentials: creds
        }
    }

    #[inline]
    pub fn principal(&self) -> &Prin {
        &self.principal
    }

    #[inline]
    pub fn creds(&self) -> &Cred {
        &self.credentials
    }

    #[inline]
    pub fn take(self) -> (Prin, Cred) {
        (self.principal, self.credentials)
    }
}

impl<Prin, Cred> TestAuthNPrinConfig<Prin, Cred> {
    #[inline]
    pub fn new(
        principal: Prin,
        creds: Vec<Cred>
    ) -> Self {
        TestAuthNPrinConfig {
            principal: principal,
            credentials: creds
        }
    }

    #[inline]
    pub fn principal(&self) -> &Prin {
        &self.principal
    }

    #[inline]
    pub fn creds(&self) -> &[Cred] {
        &self.credentials
    }

    #[inline]
    pub fn take(self) -> (Prin, Vec<Cred>) {
        (self.principal, self.credentials)
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
    pub fn allow_unsafe_ip_creds(&self) -> bool {
        self.allow_unsafe_ip_creds
    }
}
