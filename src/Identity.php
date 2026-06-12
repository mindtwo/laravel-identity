<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity;

use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Closure;

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

    /**
     * Custom callback to determine whether a client should skip the consent screen.
     */
    public static ?Closure $firstPartyClientResolver = null;

    /**
     * The default global signing algorithm. Individual clients may override via
     * the id_token_signed_response_alg column (HasOidcMetadata).
     */
    public static Algorithm $defaultSigningAlgorithm = Algorithm::RS256;

    /**
     * Register the view name for the RP-initiated logout confirmation screen.
     * Receives: ['client' => Client, 'request' => LogoutRequest, 'state' => ?string].
     */
    public static function endSessionView(Closure|string $view): void
    {
        static::$endSessionView = $view;
    }

    /**
     * Register an optional layout view that wraps the front-channel logout Blade component.
     * Receives: ['iframeUrls' => array, 'redirectUri' => ?string].
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
     * Reset all static state (useful in tests).
     */
    public static function reset(): void
    {
        static::$endSessionView = null;
        static::$frontChannelLogoutLayout = null;
        static::$firstPartyClientResolver = null;
        static::$defaultSigningAlgorithm = Algorithm::RS256;
    }
}
