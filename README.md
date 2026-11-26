# firebase-id-token-verifier

Verify **Firebase Auth ID tokens** in PHP with only `firebase/php-jwt`, no Admin SDK. Includes an **admin gate**
for panels that share a Firebase project with public apps.

```php
$verifier = new IdTokenVerifier('my-project', new GoogleCertificateSource(new StreamFetcher(), $cache));
$user = $verifier->verify($idToken);   // throws InvalidToken('expired' | 'bad_audience' | 'bad_signature' | …)

$gate = new AdminGate($verifier, ['me@example.com'], allowedProviders: ['google.com']);
$decision = $gate->check($request->header('Authorization'));   // 200 ok | 401 … | 403 not_admin | email_unverified | …
```

> Extracted and generalised from the backend I run in production for my own mobile apps
> ([Wallstudio](https://apps.apple.com/app/id6757434029) and
> [Rein](https://apps.apple.com/app/id6828685068)). There it guards the admin panel that edits the catalog the apps read.

## The problem

The admin panel and the public apps share **one** Firebase project. Anyone who installs an app gets an account in
that project. So "the token is valid" does not mean "this is an admin".

The checks have to be complete. A token library that only checks the signature still accepts a token issued for another
Firebase project.

## What gets checked

| Check | Why |
|---|---|
| `alg` is exactly `RS256`, `kid` present | rejects `alg: none` and the "HS256 signed with the public key" trick before any crypto runs |
| `kid` is one of Google's current keys; unknown → refetch **once** | Google rotates keys every few hours, so a brand-new kid is normal |
| signature against **that** key only | the token cannot pick which key verifies it |
| `exp`, `iat` (60 s leeway), `auth_time` not in the future | clock skew between servers is real; more than a minute is not |
| `aud` = project, `iss` = `https://securetoken.google.com/<project>` | a valid token from *another* Firebase project is rejected |
| `sub` non-empty, ≤ 128 chars | the Firebase spec |

Then `AdminGate` adds the policy:

1. **e-mail on an allow-list** (case-insensitive). Otherwise `403 not_admin`.
2. **`email_verified`.** Without it, someone could register `you@company.com` with a password before you ever sign
   in, and they would be on the list. Gives `403 email_unverified`, and the client can send the verification e-mail.
3. **trusted sign-in provider** (default: only `google.com`). A leaked password is then useless, and the panel inherits
   the 2-step verification of the Google account. Gives `403 provider_not_allowed`.

The order is deliberate: a stranger always gets `not_admin` and never learns whether their address is verified. If the
certificate fetch fails, the gate **fails closed** with `503 auth_unavailable` and does not blame the user's token.

## Certificates and caching

`GoogleCertificateSource` keeps the certificates for as long as Google's `Cache-Control: max-age` says (about 5–6 h). That
means **one HTTP call every few hours** per shared cache, not one per request. Two safeguards:

- `max-age` is floored at 60 s, so a broken header cannot turn into a call per request;
- forced refreshes (unknown kid) are limited to one per 30 s, so a flood of tokens with random kids cannot be used to
  hammer Google from your servers.

`Cache` is a two-method interface: `ArrayCache` for workers and tests, `FileCache` (atomic rename) for PHP-FPM, or wrap
your framework's cache (see [`examples/laravel-middleware.php`](examples/laravel-middleware.php)).

## Run the tests

```bash
composer install
composer test
```

The tests play Google themselves. They create RSA keys with self-signed X.509 certificates (the same format Google
publishes) and sign Firebase-shaped tokens, so there is no network and no real project. They cover expired, future,
foreign project, foreign issuer, forged signature, tampered payload, `alg: none`, HS256 confusion, key rotation,
unknown kid, refresh rate limiting, the provider policy and an outage.

## Layout

```
src/IdTokenVerifier.php              the spec checks
src/Access/AdminGate.php             allow-list + verified + provider policy → Decision {status, code}
src/Keys/GoogleCertificateSource.php certificates with Cache-Control caching and refresh cooldown
src/Cache/, src/Http/                tiny interfaces + dependency-free implementations
examples/                            Laravel middleware, CLI
```

MIT licensed.
