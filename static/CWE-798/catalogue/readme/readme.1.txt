# CWE-798 — Use of Hard-coded Credentials
# Catalogue entry: ReadMe API Key
# Provider: readme    Rule id (normalized): readme.1
#
# Detected by this rule:
#   - kingfisher  kingfisher.readme.1
#   - titus       kingfisher.readme.1
# Related provider rules (regex scanners, provider-level match):
#   - gitleaks    readme-api-token
#   - betterleaks readme-api-token
#
# Pattern: (?xi) \b ( rdme_(?P<RDMVAL>[a-z0-9]{70}) ) \b
#
# Fake credentials from scanner test corpora — safe to commit, not live secrets.

rdme_abcdefghijklmnopqrstuvwxyzabcdef1234567890abcdef1234567890abcdef123456
rdme_xn8s9he60fb31e9d290403d2707cce88fa820042d425fc6eb2baed4191dd88a5405987
