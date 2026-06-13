<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Contracts;

use Mindtwo\LaravelIdentity\Jwt\Algorithm;
use Mindtwo\LaravelIdentity\Jwt\KeyMaterial;

interface KeyResolver
{
    /**
     * Return the current signing key material.
     * If $preferred is given, attempt to find a key of that algorithm.
     */
    public function current(?Algorithm $preferred = null): KeyMaterial;

    /**
     * All key materials — used when building the JWKS document.
     *
     * @return iterable<KeyMaterial>
     */
    public function all(): iterable;

    /**
     * Look up a key by its `kid` identifier.
     * Returns null when the kid is unknown (e.g. rotated away).
     */
    public function byKid(string $kid): ?KeyMaterial;

    /**
     * Supported signing algorithm values for the discovery document.
     *
     * @return list<string>
     */
    public function supportedAlgs(): array;
}
