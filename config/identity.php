<?php declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | OpenID Connect Issuer
    |--------------------------------------------------------------------------
    |
    | Defaults to config('app.url'). Override here if your OP is served from
    | a different base URL than your application.
    |
    */
    'issuer' => env('IDENTITY_ISSUER'),

    /*
    |--------------------------------------------------------------------------
    | ID Token Lifetime
    |--------------------------------------------------------------------------
    |
    | Default lifetime (in seconds) for issued ID tokens. Individual clients
    | may override this via the `id_token_lifetime` column.
    |
    */
    'id_token_lifetime' => 3600,

    /*
    |--------------------------------------------------------------------------
    | Discovery Cache TTL
    |--------------------------------------------------------------------------
    |
    | How long (in seconds) to cache the /.well-known/openid-configuration
    | document. Set to 0 to disable caching.
    |
    */
    'discovery_cache_ttl' => 3600,

    /*
    |--------------------------------------------------------------------------
    | Pairwise Subject Salt
    |--------------------------------------------------------------------------
    |
    | Random secret used when computing pairwise subject identifiers. Generate
    | a value with: php artisan key:generate --show. Required when any client
    | uses subject_type=pairwise.
    |
    */
    'pairwise_salt' => env('IDENTITY_PAIRWISE_SALT'),

    /*
    |--------------------------------------------------------------------------
    | Cross-Client Token Introspection
    |--------------------------------------------------------------------------
    |
    | When false (default), a client may only introspect tokens issued to
    | itself. Set to true to allow any authenticated client to introspect
    | any token.
    |
    */
    'allow_cross_client_introspection' => false,

    /*
    |--------------------------------------------------------------------------
    | Register OpenID Scope
    |--------------------------------------------------------------------------
    |
    | When true (default), the package automatically registers the `openid`
    | scope via Passport::tokensCan(). Set to false if your app manages
    | scopes manually.
    |
    */
    'register_openid_scope' => true,

    /*
    |--------------------------------------------------------------------------
    | Signing Keys
    |--------------------------------------------------------------------------
    |
    | By default ID tokens are signed with the Passport RSA key (supporting all
    | RS* algorithms). To use dedicated keys — e.g. for EC algorithms or key
    | rotation — list them here, current (signing) key first. When non-empty,
    | the ConfigKeyResolver is used instead of the PassportKeyResolver.
    |
    | Each entry: ['private' => '<PEM>', 'public' => '<PEM>', 'algorithm' => 'RS256']
    |
    */
    'keys' => [],
];
