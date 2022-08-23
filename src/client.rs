use async_trait::async_trait;
use deadpool::managed;
use ldap3::{drive, Ldap, LdapConnAsync, LdapError, Mod, SearchEntry};
use rand::prelude::SliceRandom;
use rand::SeedableRng;
use std::collections::HashSet;
use std::sync::Arc;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    AsyncResolver,
};

use super::search::SearchAttrs;
use super::user::{LdapUser, LdapUserChangeSet};

type Pool = managed::Pool<LdapManager>;

#[derive(Clone)]
pub struct LdapClient {
    ldap: Arc<Pool>,
}

#[derive(Clone)]
struct LdapManager {
    ldap_servers: Vec<String>,
    bind_dn: String,
    bind_pw: String,
}

impl LdapManager {
    pub async fn new(bind_dn: &str, bind_pw: &str) -> Self {
        let ldap_servers = get_ldap_servers().await;

        LdapManager {
            ldap_servers,
            bind_dn: bind_dn.to_owned(),
            bind_pw: bind_pw.to_owned(),
        }
    }
}

#[async_trait]
impl managed::Manager for LdapManager {
    type Type = Ldap;
    type Error = LdapError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let (conn, mut ldap) = LdapConnAsync::new(
            self.ldap_servers
                .choose(&mut rand::rngs::StdRng::from_entropy())
                .unwrap(),
        )
        .await
        .unwrap();
        drive!(conn);

        ldap.simple_bind(&self.bind_dn, &self.bind_pw)
            .await
            .unwrap();

        Ok(ldap)
    }

    async fn recycle(&self, ldap: &mut Self::Type) -> managed::RecycleResult<Self::Error> {
        ldap.extended(ldap3::exop::WhoAmI).await?;
        Ok(())
    }
}

impl LdapClient {
    pub async fn new(bind_dn: &str, bind_pw: &str) -> Self {
        let ldap_manager = LdapManager::new(bind_dn, bind_pw).await;
        let ldap_pool = Pool::builder(ldap_manager).max_size(5).build().unwrap();

        LdapClient {
            ldap: Arc::new(ldap_pool),
        }
    }

    pub async fn search_users(&mut self, query: &str) -> Vec<LdapUser> {
        let mut ldap = self.ldap.get().await.unwrap();
        ldap.with_timeout(std::time::Duration::from_secs(5));
        let (results, _result) = ldap
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
        let mut ldap = self.ldap.get().await.unwrap();

        let (results, _result) = ldap
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
                let user = SearchEntry::construct(result.clone());
                LdapUser::from_entry(&user)
            })
            .collect()
    }

    pub async fn get_user(&mut self, uid: &str) -> Option<LdapUser> {
        let mut ldap = self.ldap.get().await.unwrap();

        ldap.with_timeout(std::time::Duration::from_secs(5));
        let (results, _result) = ldap
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
        let mut ldap = self.ldap.get().await.unwrap();

        ldap.with_timeout(std::time::Duration::from_secs(5));
        let (results, _result) = ldap
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

    pub async fn get_user_by_phone(&mut self, phone: &str) -> Option<LdapUser> {
        let mut ldap = self.ldap.get().await.unwrap();
        ldap.with_timeout(std::time::Duration::from_secs(5));
        let (results, _result) = ldap
            .search(
                "cn=users,cn=accounts,dc=csh,dc=rit,dc=edu",
                ldap3::Scope::Subtree,
                &format!("mobile={phone}"),
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
        let mut ldap = self.ldap.get().await.unwrap();

        let mut changes = Vec::new();
        if change_set.drinkBalance.is_some() {
            changes.push(Mod::Replace(
                String::from("drinkBalance"),
                HashSet::from([change_set.drinkBalance.unwrap().to_string()]),
            ));
        }
        if let Some(ib) = &change_set.ibutton {
            changes.push(Mod::Replace(
                String::from("ibutton"),
                HashSet::from_iter(ib.iter().map(|v| v.to_string())),
            ));
        }

        match ldap.modify(&change_set.dn, changes).await {
            Ok(_) => {}
            Err(e) => eprintln!("{:#?}", e),
        }
    }

    pub async fn deactivate_user(&mut self, dn: &str) {
        self.set_user_nslock(dn, true).await
    }
    pub async fn activate_user(&mut self, dn: &str) {
        self.set_user_nslock(dn, false).await
    }

    async fn set_user_nslock(&mut self, dn: &str, locked: bool) {
        let mut ldap = self.ldap.get().await.unwrap();

        let mut changes = Vec::new();
        changes.push(Mod::Replace(
            String::from("nsAccountLock"),
            HashSet::from([locked.to_string()]),
        ));

        match ldap.modify(dn, changes).await {
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
