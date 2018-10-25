ALTER TABLE accounts ADD COLUMN optout BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE accounts SET optout = 1 WHERE email = '';
