# Stripe quickstart (documentation)

> **FALSE POSITIVE — not a secret.**
> Resembles: `stripe-access-token` rules (`sk_test_` / `sk_live_` prefixes).
> Why benign: `sk_test_...` are sandbox test keys from Stripe's public docs. They
> only touch test mode, carry no real funds, and are reproduced verbatim in every
> Stripe tutorial. A real leak would be a `sk_live_` key.

```bash
curl https://api.stripe.com/v1/charges \
  -u sk_test_4eC39HqLyjWDarjtT1zdp7dc: \
  -d amount=2000 \
  -d currency=usd \
  -d source=tok_visa
```

The publishable counterpart, also non-secret, is `pk_test_TYooMQauvdEDq54NiTphI7jx`.
