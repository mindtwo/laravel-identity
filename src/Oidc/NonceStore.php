<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc;

use DateTimeImmutable;
use Illuminate\Contracts\Cache\Repository as Cache;

class NonceStore
{
    private const string PREFIX = 'identity:nonce:';

    /** Default TTL: 10 minutes (auth code lifetime). */
    private const int TTL = 600;

    /** Auth code identifier captured during the current token exchange. */
    private ?string $currentAuthCodeId = null;

    public function __construct(
        private readonly Cache $cache,
    ) {}

    /**
     * Associate the nonce, auth_time and session id with a freshly persisted auth code.
     */
    public function bindToAuthCode(
        string $authCodeId,
        ?string $nonce,
        DateTimeImmutable $authTime,
        ?string $sid = null,
    ): void {
        $this->cache->put(self::PREFIX.$authCodeId, [
            'nonce' => $nonce,
            'auth_time' => $authTime->getTimestamp(),
            'sid' => $sid,
        ], self::TTL);
    }

    /**
     * Record the auth code being exchanged so the id_token can resolve its nonce.
     */
    public function rememberAuthCode(string $authCodeId): void
    {
        $this->currentAuthCodeId = $authCodeId;
    }

    /**
     * Get auth code previously remembered.
     */
    public function currentAuthCodeId(): ?string
    {
        return $this->currentAuthCodeId;
    }

    /**
     * Retrieve (and remove) the nonce data bound to the given auth code.
     *
     * @return array{nonce: ?string, auth_time: int, sid: ?string}|null
     */
    public function pull(string $authCodeId): ?array
    {
        $key = self::PREFIX.$authCodeId;

        return $this->cache->pull($key);
    }
}
