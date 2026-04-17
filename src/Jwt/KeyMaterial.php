<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwt;

readonly class KeyMaterial
{
    public function __construct(
        public string $privateKey,
        public string $publicKey,
        public string $kid,
        public Algorithm $algorithm,
    ) {}
}
