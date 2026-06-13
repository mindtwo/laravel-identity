<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc\SubjectResolvers;

use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use RuntimeException;

class PairwiseSubjectResolver implements SubjectIdentifierResolver
{
    /**
     * {@inheritDoc}
     */
    public function resolve(OAuthenticatable $user, Client $client): string
    {
        $salt = config('identity.pairwise_salt');

        if (empty($salt)) {
            throw new RuntimeException('identity.pairwise_salt must be set to use pairwise subject identifiers.');
        }

        $sectorIdentifier = $this->sectorIdentifierFor($client);
        $raw = $sectorIdentifier.'|'.$user->getAuthIdentifier().'|'.$salt;

        return mb_rtrim(strtr(base64_encode(hash('sha256', $raw, binary: true)), '+/', '-_'), '=');
    }

    /**
     * Get the client sector identifier to for unique `sub` calculation.
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
     */
    private function sectorIdentifierFor(Client $client): string
    {
        // When the trait is applied, prefer the registered sector_identifier_uri.
        if (method_exists($client, 'getSectorIdentifierUri')) {
            $uri = $client->getSectorIdentifierUri();

            if ($uri !== null) {
                $host = parse_url($uri, PHP_URL_HOST);

                if ($host !== false && $host !== null) {
                    return $host;
                }
            }
        }

        // Fall back to the host portion of the first redirect URI.
        $redirectUris = $client->redirect_uris ?? [$client->redirect ?? ''];

        foreach ((array) $redirectUris as $uri) {
            $host = parse_url((string) $uri, PHP_URL_HOST);

            if ($host !== false && $host !== null) {
                return (string) $host;
            }
        }

        return (string) $client->getKey();
    }
}
