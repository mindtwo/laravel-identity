<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc\SubjectResolvers;

use Chiiya\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

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
