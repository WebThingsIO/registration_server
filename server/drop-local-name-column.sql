PRAGMA foreign_keys=off;

BEGIN TRANSACTION;

ALTER TABLE domains RENAME TO temp_table;

CREATE TABLE domains (
    token TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    dns_challenge TEXT NOT NULL,
    description TEXT NOT NULL,
    email TEXT NOT NULL,
    timestamp INTEGER,
    reclamation_token TEXT NOT NULL
);

INSERT INTO domains (
    token,
    name,
    dns_challenge,
    description,
    email,
    timestamp,
    reclamation_token
) SELECT
    token,
    remote_name,
    dns_challenge,
    description,
    email,
    timestamp,
    reclamation_token
FROM temp_table;

DROP TABLE temp_table;

COMMIT;
