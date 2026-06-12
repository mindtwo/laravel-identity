<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Jwt\KeyResolvers\ConfigKeyResolver;
use Chiiya\LaravelIdentity\Tests\TestCase;

class ConfigKeyResolverReachabilityTest extends TestCase
{
    private static string $publicKey = '';

    public function test_config_resolver_is_used_when_keys_are_configured(): void
    {
        $resolver = $this->app->make(KeyResolver::class);

        $this->assertInstanceOf(ConfigKeyResolver::class, $resolver);
        $this->assertSame(['RS256'], $resolver->supportedAlgs());
    }

    public function test_jwks_endpoint_publishes_the_configured_key(): void
    {
        $expectedKid = mb_substr(hash('sha256', self::$publicKey), 0, 16);

        $this->getJson('/.well-known/jwks.json')
            ->assertOk()
            ->assertJsonPath('keys.0.kid', $expectedKid)
            ->assertJsonPath('keys.0.alg', 'RS256');
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        [$private, $public] = $this->generateRsaKeypair();
        self::$publicKey = $public;

        $app['config']->set('identity.keys', [
            ['private' => $private, 'public' => $public, 'algorithm' => 'RS256'],
        ]);
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function generateRsaKeypair(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($resource, $private);
        $public = openssl_pkey_get_details($resource)['key'];

        return [$private, $public];
    }
}
