PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

ALTER TABLE emails RENAME TO temp_table;

CREATE TABLE emails (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    pending TEXT NOT NULL
);

INSERT INTO emails (
    email,
    pending
) SELECT DISTINCT
    email,
    "[]"
FROM temp_table;

DROP TABLE temp_table;

ALTER TABLE domains RENAME TO temp_table;

CREATE TABLE domains (
    name TEXT NOT NULL UNIQUE PRIMARY KEY,
    token TEXT NOT NULL,
    dns_challenge TEXT NOT NULL,
    description TEXT NOT NULL,
    email TEXT NOT NULL,
    timestamp INTEGER,
    reclamation_token TEXT NOT NULL,
    FOREIGN KEY(email) REFERENCES emails(email) ON UPDATE CASCADE ON DELETE CASCADE
);

INSERT INTO domains (
    name,
    token,
    dns_challenge,
    description,
    email,
    timestamp,
    reclamation_token
) SELECT
    name,
    token,
    dns_challenge,
    description,
    email,
    timestamp,
    reclamation_token
FROM temp_table WHERE email != "";

DROP TABLE temp_table;

COMMIT;
