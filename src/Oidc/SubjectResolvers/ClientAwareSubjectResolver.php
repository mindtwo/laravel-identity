<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc\SubjectResolvers;

use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Mindtwo\LaravelIdentity\Oidc\SubjectType;

/**
 * Dispatches `sub` resolution to the resolver matching the client's registered
 * subject_type, per OpenID Connect Core 1.0 §8.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
 */
readonly class ClientAwareSubjectResolver implements SubjectIdentifierResolver
{
    public function __construct(
        private PublicSubjectResolver $public,
        private PairwiseSubjectResolver $pairwise,
    ) {}

    public function resolve(OAuthenticatable $user, Client $client): string
    {
        return $this->resolverFor($client)->resolve($user, $client);
    }

    private function resolverFor(Client $client): SubjectIdentifierResolver
    {
        // The subject_type is only known when the client model exposes OIDC
        // metadata; otherwise the spec default (public) applies.
        if (method_exists($client, 'getSubjectType')
            && $client->getSubjectType() === SubjectType::Pairwise) {
            return $this->pairwise;
        }

        return $this->public;
    }
}
