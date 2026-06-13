<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc\Scopes;

use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Contracts\ClaimProvider;

/**
 * Provides no claims by default — host apps provide their own ClaimProvider that
 * maps from their User model to OIDC standard claim names.
 *
 * This class exists as a no-op default so the package is functional without
 * any additional configuration. Replace or supplement it by binding additional
 * ClaimProviders tagged 'identity.claims'.
 */
class StandardClaimProvider implements ClaimProvider
{
    public function getClaims(OAuthenticatable $user, array $scopes): array
    {
        return [];
    }

    public function handles(): array
    {
        return [];
    }
}
