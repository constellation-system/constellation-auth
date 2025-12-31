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
#[serde(rename = "class-id")]
#[serde(untagged)]
pub enum TestCredConfig {
    Unix { unix: PathBuf },
    IP { ip: SocketAddr }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "test-authn-config")]
#[serde(rename_all = "kebab-case")]
pub struct TestAuthNPrinConfig<Prin, Cred> {
    principal: Prin,
    creds: Vec<Cred>
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "host-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct HostAuthNUnsafeConfig {
    allow_unsafe_ip_creds: bool
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "host-authn-unsafe-config")]
#[serde(rename_all = "kebab-case")]
pub struct HostAuthNConfig {
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

impl<Prin, Cred> TestAuthNPrinConfig<Prin, Cred> {
    #[inline]
    pub fn new(
        principal: Prin,
        creds: Vec<Cred>
    ) -> Self {
        TestAuthNPrinConfig {
            principal: principal,
            creds: creds
        }
    }

    #[inline]
    pub fn principal(&self) -> &Prin {
        &self.principal
    }

    #[inline]
    pub fn creds(&self) -> &[Cred] {
        &self.creds
    }

    #[inline]
    pub fn take(self) -> (Prin, Vec<Cred>) {
        (self.principal, self.creds)
    }
}
