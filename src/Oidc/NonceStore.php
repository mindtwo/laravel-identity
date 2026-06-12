<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

use DateTimeImmutable;
use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * Bridges the nonce (and auth_time) from the authorization request to the
 * issued id_token by binding it to the authorization code identifier.
 */
class NonceStore
{
    private const PREFIX = 'identity:nonce:';

    /** Default TTL: 10 minutes (auth code lifetime). */
    private const TTL = 600;

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
        $data = $this->cache->get($key);

        if ($data !== null) {
            $this->cache->forget($key);
        }

        return $data;
    }
}
