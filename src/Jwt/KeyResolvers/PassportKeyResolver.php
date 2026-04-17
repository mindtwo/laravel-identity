<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwt\KeyResolvers;

use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Jwt\KeyMaterial;
use RuntimeException;

class PassportKeyResolver implements KeyResolver
{
    private ?KeyMaterial $cached = null;

    public function current(?Algorithm $preferred = null): KeyMaterial
    {
        return $this->cached ??= $this->load();
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
        return [$this->current()->algorithm->value];
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

        $kid = substr(hash('sha256', $publicKey), 0, 16);

        return new KeyMaterial(
            privateKey: $privateKey,
            publicKey: $publicKey,
            kid: $kid,
            algorithm: Algorithm::RS256,
        );
    }
}
