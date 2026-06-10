# AWS credential format (documentation)

> **FALSE POSITIVE — not a secret.**
> Resembles: `aws-access-token` / AWS secret access key rules.
> Why benign: these are the example credentials AWS publishes in its own docs. The
> access key id `AKIAIOSFODNN7EXAMPLE` and the secret ending in `EXAMPLEKEY` are
> reserved placeholders — most scanners explicitly allowlist the `EXAMPLE` marker.

When you configure the CLI, `~/.aws/credentials` looks like this:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Replace both values with the credentials issued to your own IAM user.
