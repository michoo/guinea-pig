-- FALSE POSITIVE — not secrets.
-- Resembles: generic high-entropy / hash rules.
-- Why benign: a DB seed migration. The values are an MD5 idempotency key (public) and
-- pre-hashed (argon2id / sha256) password digests for demo accounts. None is a usable
-- plaintext credential.

INSERT INTO migrations (id, checksum) VALUES
  ('20240117_create_users', 'd41d8cd98f00b204e9800998ecf8427e');

INSERT INTO users (email, password_hash) VALUES
  ('demo@example.com', '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'),
  ('guest@example.com', 'sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');
