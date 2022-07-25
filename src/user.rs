use lazy_static::lazy_static;
use ldap3::SearchEntry;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct LdapUser {
    pub dn: String,
    pub cn: String,
    pub uid: String,
    pub groups: Vec<String>,
    pub krbPrincipalName: String,
    pub mail: Vec<String>,
    pub mobile: Vec<String>,
    pub drinkBalance: Option<i64>,
    pub ibutton: Vec<String>,
}

impl LdapUser {
    #[must_use]
    pub fn from_entry(entry: &SearchEntry) -> Self {
        let user_attrs = &entry.attrs;
        LdapUser {
            dn: entry.dn.clone(),
            cn: get_one(user_attrs, "cn").unwrap(),
            uid: get_one(user_attrs, "uid").unwrap(),
            groups: get_groups(get_vec(user_attrs, "memberOf")),
            krbPrincipalName: get_one(user_attrs, "krbPrincipalName").unwrap(),
            mail: get_vec(user_attrs, "mail"),
            mobile: get_vec(user_attrs, "mobile"),
            ibutton: get_vec(user_attrs, "ibutton"),
            drinkBalance: get_one(user_attrs, "drinkBalance"),
        }
    }
}

fn get_one<T>(entry: &HashMap<String, Vec<String>>, field: &str) -> Option<T>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    match entry.get(field).map(|f| f.get(0).unwrap().parse::<T>()) {
        Some(result) => match result {
            Ok(r) => Some(r),
            Err(_) => None,
        },
        None => None,
    }
}

fn get_vec<T>(entry: &HashMap<String, Vec<String>>, field: &str) -> Vec<T>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    match entry.get(field) {
        Some(v) => v.iter().map(|f| f.parse::<T>().unwrap()).collect(),
        None => vec![],
    }
}

#[must_use]
pub fn get_groups(member_of: Vec<String>) -> Vec<String> {
    lazy_static! {
        static ref GROUP_REGEX: Regex =
            Regex::new(r"cn=(?P<name>\w+),cn=groups,cn=accounts,dc=csh,dc=rit,dc=edu").unwrap();
    }
    member_of
        .iter()
        .filter_map(|group| {
            GROUP_REGEX
                .captures(group)
                .map(|cap| cap["name"].to_owned())
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct LdapUserChangeSet {
    pub dn: String,
    pub drinkBalance: Option<i64>,
    pub ibutton: Option<Vec<String>>,
}
