<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Introspection;

use Chiiya\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Chiiya\LaravelIdentity\Oidc\UserProvider;
use Illuminate\Support\Facades\Date;
use Laravel\Passport\Client;
use Laravel\Passport\Token;
use Laravel\Passport\TokenRepository;

class TokenIntrospector
{
    public function __construct(
        private readonly TokenRepository $tokenRepository,
        private readonly UserProvider $userProvider,
        private readonly SubjectIdentifierResolver $subjectResolver,
    ) {}

    /**
     * Introspect a token, returning an RFC 7662 response payload.
     *
     * @return array<string, mixed>
     */
    public function introspect(string $token, ?string $tokenTypeHint, Client $requestingClient): array
    {
        $record = $this->findToken($token, $tokenTypeHint);

        if ($record === null || $record->revoked) {
            return ['active' => false];
        }

        if ($record->expires_at !== null && $record->expires_at->isPast()) {
            return ['active' => false];
        }

        if (! $this->clientMayIntrospect($record, $requestingClient)) {
            return ['active' => false];
        }

        return $this->buildActivePayload($record, $requestingClient);
    }

    private function findToken(string $token, ?string $hint): ?Token
    {
        // Attempt to find by the opaque token value stored in oauth_access_tokens.
        return $this->tokenRepository->find($token)
            ?? $this->tokenRepository->findForUser($token, null);
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
    private function buildActivePayload(Token $token, Client $requestingClient): array
    {
        $issuer = config('identity.issuer') ?: config('app.url');

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

            if ($user !== null) {
                $client = Client::find($token->client_id);
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
