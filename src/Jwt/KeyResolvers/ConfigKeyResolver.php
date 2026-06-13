<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Jwt\KeyResolvers;

use InvalidArgumentException;
use Mindtwo\LaravelIdentity\Contracts\KeyResolver;
use Mindtwo\LaravelIdentity\Jwt\Algorithm;
use Mindtwo\LaravelIdentity\Jwt\KeyMaterial;
use RuntimeException;

/**
 * Multi-key resolver for EC algorithms and key-rotation scenarios.
 *
 * Activated automatically when the `identity.keys` config array is non-empty.
 * Keys are ordered with the current (signing) key first; retiring keys remain
 * published in the JWKS so previously issued tokens still verify.
 *
 * @example config/identity.php
 *   'keys' => [
 *       ['private' => '<PEM>', 'public' => '<PEM>', 'algorithm' => 'ES256'],
 *       ['private' => '<PEM>', 'public' => '<PEM>', 'algorithm' => 'RS256'], // retiring key
 *   ],
 */
class ConfigKeyResolver implements KeyResolver
{
    /** @var list<KeyMaterial> */
    private array $keys = [];

    public function __construct(
        // @var list<array{private: string, public: string, algorithm?: string}>
        array $keys,
    ) {
        foreach ($keys as $i => $entry) {
            if (empty($entry['private']) || empty($entry['public'])) {
                throw new InvalidArgumentException("Identity key #{$i} is missing private or public value.");
            }

            $alg = Algorithm::from($entry['algorithm'] ?? Algorithm::RS256->value);
            $kid = mb_substr(hash('sha256', $entry['public']), 0, 16);
            $this->keys[] = new KeyMaterial(
                privateKey: $entry['private'],
                publicKey: $entry['public'],
                kid: $kid,
                algorithm: $alg,
            );
        }
    }

    public function current(?Algorithm $preferred = null): KeyMaterial
    {
        if (empty($this->keys)) {
            throw new RuntimeException('No identity keys configured.');
        }

        if ($preferred instanceof Algorithm) {
            foreach ($this->keys as $key) {
                if ($key->algorithm === $preferred) {
                    return $key;
                }
            }
        }

        return $this->keys[0];
    }

    public function all(): iterable
    {
        return $this->keys;
    }

    public function byKid(string $kid): ?KeyMaterial
    {
        foreach ($this->keys as $key) {
            if ($key->kid === $kid) {
                return $key;
            }
        }

        return null;
    }

    public function supportedAlgs(): array
    {
        return array_values(array_unique(array_map(fn (KeyMaterial $k) => $k->algorithm->value, $this->keys)));
    }
}
