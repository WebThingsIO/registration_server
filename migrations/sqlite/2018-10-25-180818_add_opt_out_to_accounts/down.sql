CREATE TABLE accounts_new AS SELECT
    id,
    email FROM accounts;
DROP TABLE accounts;
ALTER TABLE accounts_new RENAME TO accounts;
