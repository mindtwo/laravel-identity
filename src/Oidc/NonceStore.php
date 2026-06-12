<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

use DateTimeImmutable;
use Illuminate\Contracts\Cache\Repository as Cache;

class NonceStore
{
    private const PREFIX = 'identity:nonce:';
    private const PRE_CODE_PREFIX = 'identity:nonce_pre:';

    /** Default TTL: 10 minutes (auth code lifetime) */
    private const TTL = 600;

    public function __construct(
        private readonly Cache $cache,
    ) {}

    /**
     * Store nonce + auth_time keyed on a pre-code identifier (state+client+user).
     */
    public function storePreCode(
        string $userId,
        string $clientId,
        string $state,
        ?string $nonce,
        DateTimeImmutable $authTime,
    ): void {
        if ($nonce === null) {
            return;
        }

        $key = self::PRE_CODE_PREFIX.hash('sha256', "{$userId}|{$clientId}|{$state}");
        $this->cache->put($key, [
            'nonce' => $nonce,
            'auth_time' => $authTime->getTimestamp(),
        ], self::TTL);
    }

    /**
     * Move the nonce from the pre-code key to an auth-code-keyed entry.
     * Called when the auth code is persisted.
     */
    public function rekeyToAuthCode(string $userId, string $clientId, string $state, string $authCodeId): void
    {
        $preKey = self::PRE_CODE_PREFIX.hash('sha256', "{$userId}|{$clientId}|{$state}");
        $data = $this->cache->get($preKey);

        if ($data !== null) {
            $this->cache->put(self::PREFIX.$authCodeId, $data, self::TTL);
            $this->cache->forget($preKey);
        }
    }

    /**
     * Retrieve (and remove) nonce data for the given auth code.
     *
     * @return array{nonce: ?string, auth_time: int}|null
     */
    public function retrieve(string $authCodeId): ?array
    {
        $key = self::PREFIX.$authCodeId;
        $data = $this->cache->get($key);

        if ($data !== null) {
            $this->cache->forget($key);
        }

        return $data;
    }
}
