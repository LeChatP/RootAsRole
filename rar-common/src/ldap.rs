use serde::{Deserialize, Serialize};

use crate::ConnectionAuth;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LdapSettings {
    pub enabled: bool,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<ConnectionAuth>,
    /// The base DN for LDAP searches, e.g., "dc=example,dc=com"
    pub base_dn: String,
    /// The DN where user entries are located, e.g., "ou=users"
    pub user_dn: String,
    /// The DN where group entries are located, e.g., "ou=groups"
    pub group_dn: String,
    /// The name of the attribute used to filter user entries, e.g., "uid"
    pub user_filter: String,
    /// The name of the attribute used to filter group entries, e.g., "gid"
    pub group_filter: String,
    /// The name of the attribute used to retrieve roles for a user, e.g., "memberOf"
    pub role_filter: String,
}
//
