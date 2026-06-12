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

    public function test_builds_ec_jwk_with_full_width_coordinates(): void
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        openssl_pkey_export($key, $privateKey);
        $publicKey = openssl_pkey_get_details($key)['key'];

        $material = new KeyMaterial($privateKey, $publicKey, 'ec-kid', Algorithm::ES256);

        $resolver = $this->mock(KeyResolver::class, function (MockInterface $mock) use ($material): void {
            $mock->shouldReceive('all')->andReturn([$material]);
        });

        $jwk = (new JwksBuilder($resolver))->build()['keys'][0];

        $this->assertSame('EC', $jwk['kty']);
        $this->assertSame('P-256', $jwk['crv']);
        $this->assertSame('ES256', $jwk['alg']);

        // P-256 coordinates MUST decode to exactly 32 octets (RFC 7518 §6.2.1.2).
        $this->assertSame(32, mb_strlen($this->base64urlDecode($jwk['x']), '8bit'));
        $this->assertSame(32, mb_strlen($this->base64urlDecode($jwk['y']), '8bit'));
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

    private function base64urlDecode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
