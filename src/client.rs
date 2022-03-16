use ldap3::{drive, Ldap, LdapConnAsync, Mod, SearchEntry};
use rand::prelude::SliceRandom;
use rand::SeedableRng;
use std::collections::HashSet;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    AsyncResolver,
};

use super::search::SearchAttrs;
use super::user::{LdapUser, LdapUserChangeSet};

#[derive(Clone)]
pub struct LdapClient {
    ldap: Ldap,
}

impl LdapClient {
    pub async fn new(bind_dn: &str, bind_pw: &str) -> Self {
        let servers = get_ldap_servers().await;
        let (conn, mut ldap) = LdapConnAsync::new(
            servers
                .choose(&mut rand::rngs::StdRng::from_entropy())
                .unwrap(),
        )
        .await
        .unwrap();
        drive!(conn);

        ldap.simple_bind(bind_dn, bind_pw).await.unwrap();

        LdapClient { ldap }
    }

    pub async fn search_users(&mut self, query: &str) -> Vec<LdapUser> {
        self.ldap.with_timeout(std::time::Duration::from_secs(5));
        let (results, _result) = self
            .ldap
            .search(
                "cn=users,cn=accounts,dc=csh,dc=rit,dc=edu",
                ldap3::Scope::Subtree,
                &format!("(|(uid=*{query}*)(cn=*{query}*))"),
                SearchAttrs::default().finalize(),
            )
            .await
            .unwrap()
            .success()
            .unwrap();

        results
            .iter()
            .map(|result| {
                let user = SearchEntry::construct(result.to_owned());
                LdapUser::from_entry(&user)
            })
            .collect()
    }

    pub async fn _do_not_use_get_all_users(&mut self) -> Vec<LdapUser> {
        let (results, _result) = self
            .ldap
            .search(
                "cn=users,cn=accounts,dc=csh,dc=rit,dc=edu",
                ldap3::Scope::Subtree,
                "(objectClass=cshMember)",
                SearchAttrs::default().finalize(),
            )
            .await
            .unwrap()
            .success()
            .unwrap();

        results
            .iter()
            .map(|result| {
                let user = SearchEntry::construct(result.to_owned());
                LdapUser::from_entry(&user)
            })
            .collect()
    }

    pub async fn get_user(&mut self, uid: &str) -> Option<LdapUser> {
        self.ldap.with_timeout(std::time::Duration::from_secs(5));
        let (results, _result) = self
            .ldap
            .search(
                "cn=users,cn=accounts,dc=csh,dc=rit,dc=edu",
                ldap3::Scope::Subtree,
                &format!("uid={uid}"),
                SearchAttrs::default().finalize(),
            )
            .await
            .unwrap()
            .success()
            .unwrap();

        if results.len() == 1 {
            let user = SearchEntry::construct(results.get(0).unwrap().to_owned());
            Some(LdapUser::from_entry(&user))
        } else {
            None
        }
    }

    pub async fn get_user_by_ibutton(&mut self, ibutton: &str) -> Option<LdapUser> {
        self.ldap.with_timeout(std::time::Duration::from_secs(5));
        let (results, _result) = self
            .ldap
            .search(
                "cn=users,cn=accounts,dc=csh,dc=rit,dc=edu",
                ldap3::Scope::Subtree,
                &format!("ibutton={ibutton}"),
                SearchAttrs::default().finalize(),
            )
            .await
            .unwrap()
            .success()
            .unwrap();

        if results.len() == 1 {
            let user = SearchEntry::construct(results.get(0).unwrap().to_owned());
            Some(LdapUser::from_entry(&user))
        } else {
            None
        }
    }

    pub async fn update_user(&mut self, change_set: &LdapUserChangeSet) {
        let mut changes = Vec::new();
        if change_set.drinkBalance.is_some() {
            changes.push(Mod::Replace(
                String::from("drinkBalance"),
                HashSet::from([change_set.drinkBalance.unwrap().to_string()]),
            ))
        }
        match self.ldap.modify(&change_set.dn, changes).await {
            Ok(_) => {}
            Err(e) => eprintln!("{:#?}", e),
        }
    }
}

async fn get_ldap_servers() -> Vec<String> {
    let resolver =
        AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let response = resolver.srv_lookup("_ldap._tcp.csh.rit.edu").await.unwrap();

    // TODO: Make sure servers are working
    response
        .iter()
        .map(|record| {
            format!(
                "ldaps://{}",
                record.target().to_string().trim_end_matches('.')
            )
        })
        .collect()
}
