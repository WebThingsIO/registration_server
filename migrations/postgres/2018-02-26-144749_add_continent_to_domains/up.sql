ALTER TABLE domains ADD COLUMN continent VARCHAR(2) NOT NULL DEFAULT '';
UPDATE domains SET continent = 'NA' WHERE continent = '';
