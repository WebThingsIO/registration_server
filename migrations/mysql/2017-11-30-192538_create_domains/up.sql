CREATE TABLE domains (
    id                 INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
    name               VARCHAR(253) NOT NULL UNIQUE,
    account_id         INTEGER NOT NULL,
    token              VARCHAR(36) NOT NULL,
    description        TEXT NOT NULL,
    timestamp          BIGINT NOT NULL,
    dns_challenge      VARCHAR(63) NOT NULL DEFAULT '',
    reclamation_token  VARCHAR(36) NOT NULL DEFAULT '',
    verification_token VARCHAR(36) NOT NULL DEFAULT '',
    verified           BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY(account_id) REFERENCES accounts(id) ON UPDATE CASCADE ON DELETE CASCADE);

CREATE UNIQUE INDEX domains_name ON domains(name);
CREATE INDEX domains_timestamp ON domains(timestamp);
CREATE INDEX domains_account_id ON domains(account_id);
