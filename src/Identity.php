<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity;

use Closure;
use Laravel\Passport\Client;
use Mindtwo\LaravelIdentity\Jwt\Algorithm;

class Identity
{
    /**
     * The view to render for RP-initiated logout confirmation.
     * Set via Identity::endSessionView('view.name') in AppServiceProvider::boot().
     */
    public static Closure|string|null $endSessionView = null;

    /**
     * Optional layout view that wraps the front-channel logout Blade component.
     * When null, the component is rendered as a bare document.
     */
    public static Closure|string|null $frontChannelLogoutLayout = null;

    /** Custom callback to determine whether a client should skip the consent screen. */
    public static ?Closure $firstPartyClientResolver = null;

    /**
     * The default global signing algorithm. Individual clients may override via
     * the id_token_signed_response_alg column (HasOidcMetadata).
     */
    public static Algorithm $defaultSigningAlgorithm = Algorithm::RS256;

    /**
     * Custom scopes registered via registerScope(), keyed by scope name. Flushed
     * into the ScopeRegistrar after every provider has booted, so the calling
     * provider's boot order relative to this package does not matter.
     *
     * @var array<string, list<string>>
     */
    public static array $scopes = [];

    /**
     * Register the view for the RP-initiated logout confirmation screen: a Blade view
     * name, or a closure that receives the view data and returns a view name or any
     * response/Responsable (e.g. Inertia::render()).
     * Data: ['client' => Client, 'request' => LogoutRequest, 'state' => ?string].
     */
    public static function endSessionView(Closure|string $view): void
    {
        static::$endSessionView = $view;
    }

    /**
     * Register an optional layout view that wraps the front-channel logout Blade
     * component. Accepts the same view name or closure forms as endSessionView().
     * Data: ['iframeUrls' => list<string>, 'redirectUri' => string].
     */
    public static function frontChannelLogoutLayout(Closure|string $view): void
    {
        static::$frontChannelLogoutLayout = $view;
    }

    /**
     * Register a callback to determine whether a given client is first-party
     * and may skip the consent screen without HasOidcMetadata being applied.
     */
    public static function firstPartyClientResolver(Closure $resolver): void
    {
        static::$firstPartyClientResolver = $resolver;
    }

    /**
     * Set the default ID token signing algorithm used when no per-client override exists.
     */
    public static function signingAlgorithm(Algorithm $algorithm): void
    {
        static::$defaultSigningAlgorithm = $algorithm;
    }

    /**
     * Register a custom OIDC scope and the claim names it grants. Safe to call from
     * any service provider's register() or boot(): the scope is applied to the
     * ScopeRegistrar after all providers have booted, so it always reaches Passport,
     * discovery, and claim filtering regardless of provider order. Claim names must
     * match the keys the corresponding ClaimProvider emits (namespace your custom
     * claims, e.g. https://issuer.example/department).
     *
     * @param list<string> $claims
     */
    public static function registerScope(string $scope, array $claims): void
    {
        static::$scopes[$scope] = array_values(array_unique([...static::$scopes[$scope] ?? [], ...$claims]));
    }

    /**
     * The OpenID Provider issuer identifier. Single source of truth so the value
     * is byte-for-byte identical across the discovery document, id_token `iss`,
     * introspection, and logout validation — RPs compare it by exact string.
     */
    public static function issuer(): string
    {
        return config('identity.issuer') ?: config('app.url');
    }

    /**
     * Determine whether a client is first-party (and may skip consent). Defers to
     * the registered resolver when set, otherwise falls back to the OIDC metadata
     * trait's `isFirstParty()` flag when available.
     */
    public static function clientIsFirstParty(Client $client): bool
    {
        if (static::$firstPartyClientResolver instanceof Closure) {
            return (bool) (static::$firstPartyClientResolver)($client);
        }

        return method_exists($client, 'isFirstParty') && $client->isFirstParty();
    }

    /**
     * Reset all static state (useful in tests).
     */
    public static function reset(): void
    {
        static::$endSessionView = null;
        static::$frontChannelLogoutLayout = null;
        static::$firstPartyClientResolver = null;
        static::$defaultSigningAlgorithm = Algorithm::RS256;
        static::$scopes = [];
    }
}
