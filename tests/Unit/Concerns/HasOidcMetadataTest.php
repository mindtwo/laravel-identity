<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Unit\Concerns;

use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Oidc\SubjectType;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\TestCase;

class HasOidcMetadataTest extends TestCase
{
    public function test_defaults_are_correct(): void
    {
        $client = new TestClient;

        $this->assertSame(Algorithm::RS256, $client->getIdTokenSigningAlgorithm());
        $this->assertSame(SubjectType::Public, $client->getSubjectType());
        $this->assertFalse($client->isFirstParty());
        $this->assertFalse($client->requiresLogoutSession());
        $this->assertSame([], $client->getPostLogoutRedirectUris());
        $this->assertNull($client->getFrontchannelLogoutUri());
        $this->assertNull($client->getSectorIdentifierUri());
        $this->assertSame((int) config('identity.id_token_lifetime', 3600), $client->getIdTokenLifetimeInSeconds());
    }

    public function test_post_logout_redirect_uri_exact_match(): void
    {
        $client = new TestClient;
        $client->post_logout_redirect_uris = ['https://app.example.com/logout', 'https://other.example.com/logout'];

        $this->assertTrue($client->matchesPostLogoutRedirectUri('https://app.example.com/logout'));
        $this->assertFalse($client->matchesPostLogoutRedirectUri('https://app.example.com/logout?foo=bar'));
        $this->assertFalse($client->matchesPostLogoutRedirectUri('https://unknown.example.com/logout'));
    }

    public function test_first_party_client_skips_authorization(): void
    {
        $client = new TestClient;
        $client->first_party = true;

        $this->assertTrue($client->isFirstParty());
        $this->assertTrue($client->skipsAuthorization());
    }

    public function test_signing_algorithm_falls_back_to_rs256_for_unknown_value(): void
    {
        $client = new TestClient;
        $client->id_token_signed_response_alg = 'UNKNOWN_ALG';

        $this->assertSame(Algorithm::RS256, $client->getIdTokenSigningAlgorithm());
    }

    public function test_id_token_lifetime_uses_client_value_when_set(): void
    {
        $client = new TestClient;
        $client->id_token_lifetime = 7200;

        $this->assertSame(7200, $client->getIdTokenLifetimeInSeconds());
    }
}
