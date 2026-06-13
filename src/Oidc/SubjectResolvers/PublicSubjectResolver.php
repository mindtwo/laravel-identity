<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc\SubjectResolvers;

use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Contracts\SubjectIdentifierResolver;

class PublicSubjectResolver implements SubjectIdentifierResolver
{
    /**
     * {@inheritDoc}
     */
    public function resolve(OAuthenticatable $user, Client $client): string
    {
        return (string) $user->getAuthIdentifier();
    }
}
