table! {
    accounts (id) {
        id -> Integer,
        email -> Text,
        optout -> Bool,
    }
}

table! {
    domains (id) {
        id -> Integer,
        name -> Text,
        account_id -> Integer,
        token -> Text,
        description -> Text,
        timestamp -> BigInt,
        dns_challenge -> Text,
        reclamation_token -> Text,
        verification_token -> Text,
        verified -> Bool,
        continent -> Text,
    }
}

joinable!(domains -> accounts (account_id));

allow_tables_to_appear_in_same_query!(accounts, domains,);
