CREATE TABLE domains_new AS SELECT
    id,
    name,
    account_id,
    token,
    description,
    timestamp,
    dns_challenge,
    reclamation_token,
    verification_token,
    verified,
    continent FROM domains;
DROP TABLE domains;
ALTER TABLE domains_new RENAME TO domains;
