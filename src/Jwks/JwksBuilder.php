<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwks;

use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Jwt\KeyMaterial;
use RuntimeException;

class JwksBuilder
{
    public function __construct(
        private readonly KeyResolver $keyResolver,
    ) {}

    /**
     * Build the JWKS document.
     *
     * @return array{keys: list<array<string, string>>}
     */
    public function build(): array
    {
        $keys = [];

        foreach ($this->keyResolver->all() as $material) {
            $keys[] = $this->jwkFor($material);
        }

        return ['keys' => $keys];
    }

    /**
     * Derive a stable ETag from all published key IDs.
     */
    public function etag(): string
    {
        $kids = [];

        foreach ($this->keyResolver->all() as $material) {
            $kids[] = $material->kid;
        }

        return md5(implode('|', $kids));
    }

    /**
     * @return array<string, string>
     */
    private function jwkFor(KeyMaterial $material): array
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($material->publicKey));

        if ($details === false) {
            throw new RuntimeException('Failed to parse public key for JWK export.');
        }

        return match (true) {
            $material->algorithm->isRsa(), $material->algorithm->isPss() => $this->rsaJwk($details, $material),
            $material->algorithm->isEc() => $this->ecJwk($details, $material),
            default => throw new RuntimeException(
                "Unsupported algorithm for JWK export: {$material->algorithm->value}",
            ),
        };
    }

    /**
     * @param array<string, mixed> $details
     *
     * @return array<string, string>
     */
    private function rsaJwk(array $details, KeyMaterial $material): array
    {
        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => $material->algorithm->value,
            'kid' => $material->kid,
            'n' => JwkEncoder::encodeBignum($details['rsa']['n']),
            'e' => JwkEncoder::encodeBignum($details['rsa']['e']),
        ];
    }

    /**
     * @param array<string, mixed> $details
     *
     * @return array<string, string>
     */
    private function ecJwk(array $details, KeyMaterial $material): array
    {
        $crv = match ($material->algorithm) {
            Algorithm::ES256 => 'P-256',
            Algorithm::ES384 => 'P-384',
            Algorithm::ES512 => 'P-521',
            default => throw new RuntimeException("Unsupported EC algorithm: {$material->algorithm->value}"),
        };

        return [
            'kty' => 'EC',
            'use' => 'sig',
            'alg' => $material->algorithm->value,
            'kid' => $material->kid,
            'crv' => $crv,
            'x' => JwkEncoder::base64url($details['ec']['x']),
            'y' => JwkEncoder::base64url($details['ec']['y']),
        ];
    }
}
