CREATE DATABASE IF NOT EXISTS ctf;
USE ctf;
CREATE TABLE secrets (id INT PRIMARY KEY, flag VARCHAR(64));
INSERT INTO secrets VALUES (1, 'flag{mysql_empty_root_password}');
