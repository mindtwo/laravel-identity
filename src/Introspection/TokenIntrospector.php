<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Introspection;

use Chiiya\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Chiiya\LaravelIdentity\Identity;
use Chiiya\LaravelIdentity\Oidc\UserProvider;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Throwable;

readonly class TokenIntrospector
{
    public function __construct(
        private UserProvider $userProvider,
        private SubjectIdentifierResolver $subjectResolver,
    ) {}

    /**
     * Introspect a token, returning an RFC 7662 response payload.
     *
     * Only access tokens are introspectable: Passport refresh tokens are opaque
     * encrypted blobs, so the optional `token_type_hint` carries no optimization
     * value here and is intentionally not part of this signature (RFC 7662 §2.1).
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
     *
     * @return array<string, mixed>
     */
    public function introspect(string $token, Client $requestingClient): array
    {
        $record = $this->findToken($token);

        if (! $record instanceof Token) {
            return ['active' => false];
        }

        if (! $this->clientMayIntrospect($record, $requestingClient)) {
            return ['active' => false];
        }

        return $this->buildActivePayload($record);
    }

    private function findToken(string $token): ?Token
    {
        $id = $this->accessTokenId($token);

        if ($id === null) {
            return null;
        }

        /** @var Token|null $record */
        $record = Passport::tokenModel()::query()->find($id);

        if ($record === null || $record->revoked) {
            return null;
        }

        if ($record->expires_at !== null && $record->expires_at->isPast()) {
            return null;
        }

        return $record;
    }

    /**
     * Extract the access token identifier (`jti`) from a JWT-encoded Passport access token.
     */
    private function accessTokenId(string $token): ?string
    {
        try {
            $parsed = new Parser(new JoseEncoder)->parse($token);
        } catch (Throwable) {
            return null;
        }

        if (! $parsed instanceof Plain) {
            return null;
        }

        $jti = $parsed->claims()->get(RegisteredClaims::ID);

        return is_string($jti) ? $jti : null;
    }

    private function clientMayIntrospect(Token $token, Client $requestingClient): bool
    {
        if (config('identity.allow_cross_client_introspection', false)) {
            return true;
        }

        return $token->client_id === (string) $requestingClient->getKey();
    }

    /**
     * @return array<string, mixed>
     */
    private function buildActivePayload(Token $token): array
    {
        $issuer = Identity::issuer();

        $payload = [
            'active' => true,
            'scope' => $token->scopes ? implode(' ', $token->scopes) : '',
            'client_id' => $token->client_id,
            'token_type' => 'Bearer',
            'exp' => $token->expires_at?->getTimestamp(),
            'iat' => $token->created_at?->getTimestamp(),
            'iss' => $issuer,
            'jti' => $token->id,
            'aud' => $token->client_id,
        ];

        if ($token->user_id !== null) {
            $user = $this->userProvider->findById($token->user_id);

            if ($user instanceof OAuthenticatable) {
                /** @var Client|null $client */
                $client = Passport::clientModel()::query()->find($token->client_id);
                $payload['sub'] = $client !== null
                    ? $this->subjectResolver->resolve($user, $client)
                    : (string) $user->getAuthIdentifier();

                if (method_exists($user, 'getEmailForPasswordReset')) {
                    $payload['username'] = $user->getEmailForPasswordReset();
                }
            }
        }

        return array_filter($payload, fn ($v) => $v !== null);
    }
}
