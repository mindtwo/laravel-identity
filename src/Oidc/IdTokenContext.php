<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

use Chiiya\LaravelIdentity\Jwt\Algorithm;
use DateTimeImmutable;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

readonly class IdTokenContext
{
    /**
     * @param array<string, mixed> $claims
     * @param list<string> $scopes
     */
    public function __construct(
        public OAuthenticatable $user,
        public Client $client,
        public array $scopes,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public DateTimeImmutable $authTime,
        public array $claims,
        public ?string $nonce,
        public ?string $sid,
        public string $subject,
        public Algorithm $algorithm = Algorithm::RS256,
    ) {}
}
