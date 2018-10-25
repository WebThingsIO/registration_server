use schema::{accounts, domains};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, AsChangeset, Identifiable, Queryable)]
#[table_name = "accounts"]
pub struct Account {
    pub id: i32,
    pub email: String,
    pub optout: bool,
}

#[derive(Insertable)]
#[table_name = "accounts"]
pub struct NewAccount<'a> {
    pub email: &'a str,
    pub optout: bool,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    AsChangeset,
    Associations,
    Identifiable,
    Queryable,
)]
#[table_name = "domains"]
#[belongs_to(Account)]
pub struct Domain {
    pub id: i32,
    pub name: String,
    pub account_id: i32,
    pub token: String,
    pub description: String,
    pub timestamp: i64,
    pub dns_challenge: String,
    pub reclamation_token: String,
    pub verification_token: String,
    pub verified: bool,
    pub continent: String,
}

#[derive(Insertable)]
#[table_name = "domains"]
pub struct NewDomain<'a> {
    pub name: &'a str,
    pub account_id: i32,
    pub token: &'a str,
    pub description: &'a str,
    pub timestamp: i64,
    pub dns_challenge: &'a str,
    pub reclamation_token: &'a str,
    pub verification_token: &'a str,
    pub verified: bool,
    pub continent: &'a str,
}
