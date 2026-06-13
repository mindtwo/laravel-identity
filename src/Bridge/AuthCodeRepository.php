<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Bridge;

use DateTimeImmutable;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use Mindtwo\LaravelIdentity\Oidc\NonceStore;

/**
 * Extends Passport's auth code repository to carry the OIDC nonce and auth_time
 * from the authorization request (stashed in the session) onto the issued auth
 * code, and to expose the auth code identifier during token exchange so the
 * id_token can resolve its nonce.
 */
class AuthCodeRepository extends PassportAuthCodeRepository
{
    public function __construct(
        private readonly NonceStore $nonceStore,
    ) {}

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        parent::persistNewAuthCode($authCodeEntity);

        // Runs within the (web) authorization request, so the session is available.
        $data = session()->pull('identity.oidc_auth');

        if (is_array($data)) {
            $this->nonceStore->bindToAuthCode(
                $authCodeEntity->getIdentifier(),
                $data['nonce'] ?? null,
                new DateTimeImmutable()->setTimestamp((int) ($data['auth_time'] ?? time())),
                $data['sid'] ?? null,
            );
        }
    }

    public function revokeAuthCode(string $codeId): void
    {
        // Called during code → token exchange, before the id_token is built.
        $this->nonceStore->rememberAuthCode($codeId);

        parent::revokeAuthCode($codeId);
    }
}
