PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

ALTER TABLE emails RENAME TO temp_table;

CREATE TABLE accounts (
    id    INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE
);

INSERT INTO accounts (
    email
) SELECT DISTINCT
    email
FROM temp_table;

INSERT OR IGNORE INTO accounts (email) VALUES ("");

DROP TABLE temp_table;

ALTER TABLE domains RENAME TO temp_table;

CREATE TABLE domains (
    name               TEXT NOT NULL UNIQUE PRIMARY KEY,
    account_id         INTEGER NOT NULL,
    token              TEXT NOT NULL,
    description        TEXT NOT NULL,
    timestamp          INTEGER NOT NULL,
    dns_challenge      TEXT NOT NULL DEFAULT '',
    reclamation_token  TEXT NOT NULL DEFAULT '',
    verification_token TEXT NOT NULL DEFAULT '',
    verified           BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY(account_id) REFERENCES accounts(id)
        ON UPDATE CASCADE ON DELETE CASCADE
);

INSERT INTO domains (
    name,
    account_id,
    token,
    description,
    timestamp,
    dns_challenge,
    reclamation_token,
    verification_token,
    verified
) SELECT
    temp_table.name,
    accounts.id,
    temp_table.token,
    temp_table.description,
    temp_table.timestamp,
    temp_table.dns_challenge,
    temp_table.reclamation_token,
    "",
    CASE WHEN length(temp_table.email) > 0 THEN 1 ELSE 0 END
FROM temp_table INNER JOIN accounts ON accounts.email = temp_table.email;

DROP TABLE temp_table;

COMMIT;
