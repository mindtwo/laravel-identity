<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Contracts;

use DateTimeImmutable;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

interface SessionIdResolver
{
    /**
     * Return (or create) the stable `sid` for the current request context,
     * recording the authentication time so it can be replayed on refresh.
     */
    public function forCurrentRequest(OAuthenticatable $user, Client $client, DateTimeImmutable $authTime): string;

    /**
     * Recover the active `sid` and original `auth_time` for a (user, client)
     * pair — used when reissuing an id_token on the refresh_token grant, where
     * no web session or authorization code is available.
     *
     * @return array{sid: string, auth_time: int}|null
     */
    public function recover(OAuthenticatable $user, Client $client): ?array;

    /**
     * Revoke all active session ids for the given user (called on logout).
     */
    public function invalidate(OAuthenticatable $user): void;
}
