<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Tests\TestCase;

class JwksEndpointTest extends TestCase
{
    public function test_returns_keys_array(): void
    {
        $response = $this->getJson('/.well-known/jwks.json');

        $response->assertOk();
        $response->assertJsonStructure(['keys' => [['kty', 'use', 'alg', 'kid', 'n', 'e']]]);
        $response->assertHeader('Cache-Control', 'max-age=3600, public');
    }

    public function test_returns_304_when_etag_matches(): void
    {
        $first = $this->getJson('/.well-known/jwks.json');
        $etag = $first->headers->get('ETag');

        $response = $this->withHeaders(['If-None-Match' => $etag])
            ->getJson('/.well-known/jwks.json');

        $response->assertStatus(304);
    }

    public function test_kid_is_present_in_each_key(): void
    {
        $response = $this->getJson('/.well-known/jwks.json');

        foreach ($response->json('keys') as $key) {
            $this->assertArrayHasKey('kid', $key);
            $this->assertNotEmpty($key['kid']);
        }
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();
        $this->artisan('passport:keys', ['--force' => true])->run();
    }
}
