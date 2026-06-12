<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwt\KeyResolvers;

use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Exceptions\UnsupportedSigningAlgorithm;
use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Jwt\KeyMaterial;
use RuntimeException;

class PassportKeyResolver implements KeyResolver
{
    private ?KeyMaterial $cached = null;

    public function current(?Algorithm $preferred = null): KeyMaterial
    {
        $base = $this->cached ??= $this->load();

        if (! $preferred instanceof Algorithm || $preferred === $base->algorithm) {
            return $base;
        }

        // Passport's signing key is RSA, so it can produce every RS* variant from
        // the same key material — only the digest differs.
        if (! $preferred->isRsa()) {
            throw new UnsupportedSigningAlgorithm(
                "The Passport signing key cannot issue {$preferred->value} tokens. "
                .'Register a custom KeyResolver to support EC algorithms.',
            );
        }

        return new KeyMaterial($base->privateKey, $base->publicKey, $base->kid, $preferred);
    }

    public function all(): iterable
    {
        yield $this->current();
    }

    public function byKid(string $kid): ?KeyMaterial
    {
        $material = $this->current();

        return $material->kid === $kid ? $material : null;
    }

    public function supportedAlgs(): array
    {
        // A single RSA key supports all RSASSA-PKCS1 (RS*) algorithms.
        return [Algorithm::RS256->value, Algorithm::RS384->value, Algorithm::RS512->value];
    }

    private function load(): KeyMaterial
    {
        $publicPath = storage_path('oauth-public.key');
        $privatePath = storage_path('oauth-private.key');

        if (! file_exists($publicPath) || ! file_exists($privatePath)) {
            throw new RuntimeException('Passport keys not found. Run: php artisan passport:keys');
        }

        $publicKey = file_get_contents($publicPath);
        $privateKey = file_get_contents($privatePath);

        if ($publicKey === false || $privateKey === false) {
            throw new RuntimeException('Failed to read Passport key files.');
        }

        $kid = mb_substr(hash('sha256', $publicKey), 0, 16);

        return new KeyMaterial(
            privateKey: $privateKey,
            publicKey: $publicKey,
            kid: $kid,
            algorithm: Algorithm::RS256,
        );
    }
}
