<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Contracts;

use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

interface SubjectIdentifierResolver
{
    /**
     * Resolve the `sub` claim for the given user and client.
     */
    public function resolve(OAuthenticatable $user, Client $client): string;
}
