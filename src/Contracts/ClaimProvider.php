<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Contracts;

use Laravel\Passport\Contracts\OAuthenticatable;

interface ClaimProvider
{
    /**
     * Return the claims this provider contributes for the given user and granted scopes.
     *
     * @return array<string, mixed>
     */
    public function getClaims(OAuthenticatable $user, array $scopes): array;

    /**
     * The scope names this provider handles. Return an empty array to always run.
     *
     * @return list<string>
     */
    public function handles(): array;
}
