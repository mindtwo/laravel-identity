<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Unit\Jwks;

use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Jwks\JwksBuilder;
use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Jwt\KeyMaterial;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Mockery\MockInterface;

class JwksBuilderTest extends TestCase
{
    private string $testPrivateKey;
    private string $testPublicKey;

    public function test_builds_rsa_jwk_with_required_fields(): void
    {
        $kid = mb_substr(hash('sha256', $this->testPublicKey), 0, 16);
        $material = new KeyMaterial($this->testPrivateKey, $this->testPublicKey, $kid, Algorithm::RS256);

        $resolver = $this->mock(KeyResolver::class, function (MockInterface $mock) use ($material): void {
            $mock->shouldReceive('all')->andReturn([$material]);
        });

        $builder = new JwksBuilder($resolver);
        $result = $builder->build();

        $this->assertArrayHasKey('keys', $result);
        $this->assertCount(1, $result['keys']);

        $jwk = $result['keys'][0];
        $this->assertSame('RSA', $jwk['kty']);
        $this->assertSame('sig', $jwk['use']);
        $this->assertSame('RS256', $jwk['alg']);
        $this->assertSame($kid, $jwk['kid']);
        $this->assertArrayHasKey('n', $jwk);
        $this->assertArrayHasKey('e', $jwk);
    }

    public function test_etag_is_deterministic(): void
    {
        $kid = 'abc123';
        $material = new KeyMaterial($this->testPrivateKey, $this->testPublicKey, $kid, Algorithm::RS256);

        $resolver = $this->mock(KeyResolver::class, function (MockInterface $mock) use ($material): void {
            $mock->shouldReceive('all')->andReturn([$material]);
            $mock->shouldReceive('all')->andReturn([$material]);
        });

        $builder = new JwksBuilder($resolver);

        $this->assertSame($builder->etag(), $builder->etag());
    }

    public function test_multiple_keys_included_in_jwks(): void
    {
        $kid1 = 'key1';
        $kid2 = 'key2';
        $material1 = new KeyMaterial($this->testPrivateKey, $this->testPublicKey, $kid1, Algorithm::RS256);
        $material2 = new KeyMaterial($this->testPrivateKey, $this->testPublicKey, $kid2, Algorithm::RS256);

        $resolver = $this->mock(KeyResolver::class, function (MockInterface $mock) use ($material1, $material2): void {
            $mock->shouldReceive('all')->andReturn([$material1, $material2]);
        });

        $builder = new JwksBuilder($resolver);
        $result = $builder->build();

        $this->assertCount(2, $result['keys']);
        $this->assertSame($kid1, $result['keys'][0]['kid']);
        $this->assertSame($kid2, $result['keys'][1]['kid']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);
        $this->testPrivateKey = $privateKey;
        $this->testPublicKey = $details['key'];
    }
}
