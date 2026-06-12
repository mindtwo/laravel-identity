<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Contracts;

use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

interface SessionIdResolver
{
    /**
     * Return (or create) the stable `sid` for the current request context.
     */
    public function forCurrentRequest(OAuthenticatable $user, Client $client): string;

    /**
     * Revoke all active session ids for the given user (called on logout).
     */
    public function invalidate(OAuthenticatable $user): void;
}
