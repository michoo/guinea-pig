# CWE-798 — False Positives

The companion to `../catalogue/`. Each file here is **benign source code that resembles
a secret-detection rule but must NOT be flagged**. Use them to measure scanner precision
(false-positive rate) the same way the catalogue measures recall.

One file per false-positive class. Each starts with a header comment stating which rule
it resembles and why it is safe.

| File | Resembles | Why it's benign |
|---|---|---|
| `github_actions_sha_pins.yml` | hex token / generic | git commit SHAs pinning Actions (public ids) |
| `subresource_integrity.html` | base64 secret | SRI asset digests, meant to be published |
| `package_lock_integrity.json` | base64 secret | npm `sha512-` integrity hashes |
| `aws_documented_example_keys.md` | aws-access-token | AWS's reserved `EXAMPLE` placeholders |
| `stripe_docs_test_key.md` | stripe-access-token | `sk_test_` sandbox key from Stripe docs |
| `jwt_public_demo.txt` | jwt | jwt.io demo token signed with a known key |
| `uuid_identifiers.json` | hex token | random UUID resource ids |
| `placeholder_env.example` | generic-api-key / password | `.env.example` placeholders (`changeme`, `xxx`) |
| `bcrypt_password_hashes.txt` | password / high-entropy | one-way bcrypt hashes |
| `tailwind_components.jsx` | base64 / high-entropy | Tailwind class-name strings |
| `ssh_public_keys.pub` | private-key / base64 | SSH **public** keys |
| `sha256_checksums.txt` | hex token | published release checksums |
| `test_fixtures.py` | password / api-key | low-entropy unit-test fixtures |
| `local_connection_strings.conf` | connection-string | localhost defaults (`postgres/postgres`) |
| `data_uri_assets.css` | base64 secret | inline `data:` image payloads |
| `pgp_public_key.asc` | private-key | armored PGP **public** key block |
| `color_constants.ts` | hex token | CSS/ARGB color constants |
| `mock_tokens.spec.ts` | bearer / jwt / api-key | mock tokens in tests |
| `i18n_translations.json` | generic-secret | translation keys named `token`/`secret` |
| `otpauth_sample.txt` | base32 TOTP seed | RFC 6238 demo seed |
| `migration_seed_hashes.sql` | high-entropy / hash | seed checksums + pre-hashed passwords |

A scanner that reports any of these is producing a false positive.
