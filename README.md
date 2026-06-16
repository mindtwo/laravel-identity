[![mindtwo GmbH](https://www.mindtwo.de/downloads/doodles/github/repository-header.png)](https://www.mindtwo.de/)

<div align="center">
  <p align="center">
    <img src="https://img.shields.io/github/check-runs/mindtwo/laravel-identity/master">
    <img src="https://img.shields.io/badge/php-%3E%3D%208.4-8892BF.svg">
    <img src="https://img.shields.io/badge/laravel-13-FF2D20.svg">
  </p>

  <strong>
    <h2 align="center">Laravel Identity</h2>
  </strong>

  <p align="center">
    The missing OIDC identity layer for Laravel Passport
  </p>
</div>
<br />

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Endpoints](#endpoints)
- [Logout](#logout)
    - [RP-Initiated Logout](#rp-initiated-logout)
    - [Front-Channel Logout](#front-channel-logout)
- [Configuration](#configuration)
- [Subject Types](#subject-types)
- [Signing Keys and Rotation](#signing-keys-and-rotation)
- [First-Party Clients](#first-party-clients)
- [Events](#events)
- [Extension Points](#extension-points)
- [Token Introspection](#token-introspection)
- [Testing](#testing)
- [License](#license)



## Features

Laravel Identity is an OpenID Connect (OIDC) identity layer for [Laravel Passport](https://laravel.com/docs/passport). It turns a Passport OAuth2 server into a 
spec-compliant OpenID Provider (OP) by adding ID tokens, a UserInfo endpoint, discovery, JWKS, token introspection, 
and both front-channel and RP-initiated logout.

Implemented specifications:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Token Introspection (RFC 7662)](https://datatracker.ietf.org/doc/html/rfc7662)
- [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)

## Requirements

- PHP 8.4+
- Laravel 13 / Passport 13

## Installation

```bash
composer require mindtwo/laravel-identity
```

Run Passport's installer first (if you have not already), then publish this package's migrations and run 
them. The migrations alter Passport's `oauth_clients` table.

```bash
php artisan passport:install
php artisan vendor:publish --tag=identity-migrations
php artisan migrate
```

Publish the config if you need to change defaults:

```bash
php artisan vendor:publish --tag=identity-config
```

## Quick start

### 1. Add OIDC metadata to your Client model

Extend Passport's client and apply the `HasOidcMetadata` trait, then register it with Passport:

```php
use Mindtwo\LaravelIdentity\Concerns\HasOidcMetadata;
use Laravel\Passport\Client as PassportClient;

class Client extends PassportClient
{
    use HasOidcMetadata;
}
```

```php
// AppServiceProvider::boot()
use Laravel\Passport\Passport;

Passport::useClientModel(\App\Models\Client::class);
```

The trait reads OIDC settings from these (nullable) columns, added by the migration:

| Column | Purpose |
| --- | --- |
| `subject_type` | `public` (default) or `pairwise` — selects the `sub` resolver |
| `sector_identifier_uri` | Host used to compute pairwise `sub` (falls back to redirect host) |
| `id_token_signed_response_alg` | Per-client signing algorithm (e.g. `RS512`) |
| `id_token_lifetime` | Per-client ID token lifetime in seconds |
| `default_max_age` | Forces re-authentication when the session is older, even if the request omits `max_age` |
| `first_party` | First-party clients skip the consent screen |
| `frontchannel_logout_uri` | RP endpoint loaded in an iframe on logout |
| `frontchannel_logout_session_required` | Append `iss`/`sid` to the front-channel logout URI |
| `post_logout_redirect_uris` | JSON array of allowed `post_logout_redirect_uri` values |

### 2. Expose claims from your User model

Your authenticatable must implement Passport's `OAuthenticatable`. To emit standard OIDC claims, 
register one or more `ClaimProvider`s and tag them `identity.claims`:

```php
use Mindtwo\LaravelIdentity\Contracts\ClaimProvider;
use Laravel\Passport\Contracts\OAuthenticatable;

class UserClaimProvider implements ClaimProvider
{
    public function getClaims(OAuthenticatable $user, array $scopes): array
    {
        return array_filter([
            'name' => $user->name,
            'email' => $user->email,
            'email_verified' => $user->hasVerifiedEmail(),
        ]);
    }

    /** Scopes this provider answers to. Return [] to always run. */
    public function handles(): array
    {
        return ['profile', 'email'];
    }
}
```

```php
// AppServiceProvider::register()
$this->app->tag(UserClaimProvider::class, 'identity.claims');
```

Claims are filtered against the granted scopes (`profile`, `email`, `address`, `phone`, …) before they reach 
the ID token and UserInfo response, so a provider can safely return everything it knows.

### 3. Provide `auth_time` (optional, recommended)

To support `max_age` re-authentication and an accurate `auth_time` claim, expose the moment the user authenticated:

```php
public function getAuthTime(): \DateTimeInterface
{
    return $this->last_login_at ?? now();
}
```

When the method is absent, `auth_time` defaults to the current request time.

## Endpoints

All endpoints are registered automatically:

| Endpoint | Route name | Description |
| --- | --- | --- |
| `GET /.well-known/openid-configuration` | `identity.discovery` | Discovery document (cached) |
| `GET /.well-known/jwks.json` | `identity.jwks` | Public signing keys (JWKS, ETag-cached) |
| `GET\|POST /oauth/userinfo` | `identity.userinfo` | UserInfo (requires `openid` scope) |
| `POST /oauth/introspect` | `identity.introspect` | RFC 7662 introspection (client-authenticated) |
| `GET\|POST /oauth/logout` | `identity.end_session` | RP-Initiated Logout |
| `GET /oauth/logout/frontchannel` | `identity.frontchannel_logout` | Front-channel logout iframe page |

The ID token is added to the standard Passport token response (`/oauth/token`) whenever the `openid` scope is granted.

## Logout

### RP-Initiated Logout

Send the user to `identity.end_session` with an `id_token_hint` (or `client_id`), optional 
`post_logout_redirect_uri` (must be registered on the client) and `state`. The subject in `id_token_hint` is 
matched against the current user through the same subject resolver used at issuance, so pairwise subjects work correctly.

Non-first-party clients are shown a confirmation screen. Register the view:

```php
// AppServiceProvider::boot()
Identity::endSessionView('auth.logout-confirm');
// receives ['client' => Client, 'request' => LogoutRequest, 'state' => ?string]
```

First-party clients (see [First-party clients](#first-party-clients)) skip confirmation.

### Front-Channel Logout

On logout the package renders a page with a hidden iframe per active session whose client registered 
a `frontchannel_logout_uri`. Sessions are tracked in `oidc_sessions`, and each iframe carries the same `sid` 
embedded in that session's ID token.

To brand the page, point `Identity::frontChannelLogoutLayout` at your own view and 
**embed the supplied Blade component** — you get the iframe-loading and redirect logic for free, you 
only style around it:

```blade
{{-- resources/views/layouts/logout.blade.php --}}
<x-app-layout>
    <p>Signing you out…</p>
    <x-identity::front-channel-logout :urls="$iframeUrls" :redirect="$redirectUri ?? '/'" />
</x-app-layout>
```

```php
Identity::frontChannelLogoutLayout('layouts.logout');
// your view receives ['iframeUrls' => array, 'redirectUri' => ?string]
```

The `<x-identity::front-channel-logout>` component renders the hidden iframes and the JS that redirects once 
they have loaded (or after a timeout). If you don't register a layout, the package renders a minimal 
default page built from the same component.

## Configuration

`config/identity.php`:

| Key | Default | Description |
| --- | --- | --- |
| `issuer` | `config('app.url')` | OP issuer identifier (`IDENTITY_ISSUER`) |
| `id_token_lifetime` | `3600` | Default ID token lifetime (seconds) |
| `discovery_cache_ttl` | `3600` | Discovery document cache TTL; `0` disables |
| `pairwise_salt` | `null` | Secret for pairwise `sub` (`IDENTITY_PAIRWISE_SALT`); required for `pairwise` clients |
| `allow_cross_client_introspection` | `false` | Allow a client to introspect tokens it did not own |
| `register_openid_scope` | `true` | Auto-register OIDC scopes via `Passport::tokensCan()` |
| `keys` | `[]` | Dedicated signing keys (see [Signing keys](#signing-keys-and-rotation)) |

### Static configuration (`Identity`)

Set in `AppServiceProvider::boot()`:

```php
use Mindtwo\LaravelIdentity\Identity;
use Mindtwo\LaravelIdentity\Jwt\Algorithm;

Identity::signingAlgorithm(Algorithm::ES256);                  // global default alg
Identity::endSessionView('auth.logout-confirm');               // RP logout screen
Identity::frontChannelLogoutLayout('layouts.logout');          // optional layout
Identity::firstPartyClientResolver(fn ($client) => $client->trusted);
```

## Subject types

`sub` resolution is dispatched per client by `ClientAwareSubjectResolver`:

- **public** (default) — `sub` is the user's identifier.
- **pairwise** — `sub` is a salted hash unique per sector, computed by `PairwiseSubjectResolver` from 
`sector_identifier_uri` (or the redirect host) plus `pairwise_salt`. Set `identity.pairwise_salt` when any client uses it.

Set a client's `subject_type` column to `pairwise` to opt in.

## Signing keys and rotation

By default, the **Passport RSA key** signs ID tokens and backs every `RS*` algorithm (`RS256`/`RS384`/`RS512`), 
selectable globally or per client.

For EC algorithms or key rotation, list dedicated keys in `identity.keys` (current/signing key first). When 
non-empty, `ConfigKeyResolver` is used automatically and every listed key is published in the JWKS so previously 
issued tokens keep verifying:

```php
'keys' => [
    ['private' => file_get_contents(storage_path('oidc/current.key')),
     'public'  => file_get_contents(storage_path('oidc/current.pub')),
     'algorithm' => 'ES256'],
    ['private' => file_get_contents(storage_path('oidc/previous.key')),
     'public'  => file_get_contents(storage_path('oidc/previous.pub')),
     'algorithm' => 'RS256'], // retiring key, still published
],
```

## First-party clients

A client is treated as first-party (and skips the consent screen and logout confirmation) when either:

- a resolver registered via `Identity::firstPartyClientResolver()` returns `true`, or
- the client model uses `HasOidcMetadata` and its `first_party` column is `true`.

## Events

Listen via Laravel's event system:

| Event | Dispatched when |
| --- | --- |
| `AuthorizationRequestValidated` | An OIDC authorization request passes validation (carries the `AuthRequestContext`) |
| `IdTokenIssued` | An ID token is minted (carries the `IdTokenContext` and the encoded token) |
| `UserLoggedOut` | A user logs out (carries the initiating client, or `null` for local logout) |

For logout side effects that **must complete before the redirect** (e.g. revoking tokens), implement 
`LogoutEventListener` and tag it `identity.logout_listeners` — these run synchronously, ahead of the dispatched event:

```php
$this->app->tag(RevokeTokensOnLogout::class, 'identity.logout_listeners');
```

## Extension points

Every collaborator is bound to a contract and can be swapped in the container. Respecting custom Passport 
models, all client/user lookups go through `Passport::clientModel()` and the configured auth provider.

| Contract | Default | Responsibility |
| --- | --- | --- |
| `KeyResolver` | `PassportKeyResolver` / `ConfigKeyResolver` | Signing key material + JWKS |
| `SubjectIdentifierResolver` | `ClientAwareSubjectResolver` | The `sub` claim |
| `ScopeRegistrar` | `StandardScopeRegistrar` | Scope → claim mapping |
| `SessionIdResolver` | `SidManager` | `sid` issuance and revocation |
| `DiscoveryDocumentBuilder` | `DefaultDiscoveryBuilder` | The discovery document |

To add a custom scope and the claims it grants, call `Identity::registerScope()` from
any service provider's `register()` or `boot()` — order relative to this package does
not matter, and the scope reaches Passport, discovery, and claim filtering automatically:

```php
use Mindtwo\LaravelIdentity\Identity;

// AppServiceProvider::boot()
Identity::registerScope('org', [
    'https://issuer.example/department',
    'https://issuer.example/team',
]);
```

The claim names must match the keys your `ClaimProvider` emits; namespace any
non-standard claims with a URI you own so they cannot collide with standard ones.

To replace a collaborator entirely, swap its container binding:

```php
$this->app->extend(ScopeRegistrar::class, function ($registrar) {
    // return your own ScopeRegistrar implementation
    return $registrar;
});
```

## Token introspection

`POST /oauth/introspect` implements RFC 7662. Clients authenticate via `client_secret_basic` or 
`client_secret_post`. By default a client may only introspect its own tokens; set `allow_cross_client_introspection` 
to `true` to lift that restriction. Revoked or expired tokens return `{"active": false}`.

## Testing

```bash
composer test       # or: vendor/bin/phpunit
```

## License

MIT
