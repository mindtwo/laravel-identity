<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

use Chiiya\LaravelIdentity\Contracts\SessionIdResolver;
use Chiiya\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Chiiya\LaravelIdentity\Events\IdTokenIssued;
use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Jwt\JwtIssuer;
use DateTimeImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Throwable;

class IdTokenResponseType extends BearerTokenResponse
{
    public function __construct(
        private readonly JwtIssuer $jwtIssuer,
        private readonly ClaimAggregator $claimAggregator,
        private readonly SubjectIdentifierResolver $subjectResolver,
        private readonly NonceStore $nonceStore,
        private readonly SessionIdResolver $sidResolver,
        private readonly UserProvider $userProvider,
        private readonly Dispatcher $events,
    ) {}

    /**
     * @return array<string, string>
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        $scopes = array_map(fn ($scope) => $scope->getIdentifier(), $accessToken->getScopes());

        if (! in_array('openid', $scopes, strict: true)) {
            return [];
        }

        $userIdentifier = $accessToken->getUserIdentifier();

        if ($userIdentifier === null) {
            return [];
        }

        /** @var OAuthenticatable|null $user */
        $user = $this->userProvider->findById($userIdentifier);

        if ($user === null) {
            return [];
        }

        $clientId = $accessToken->getClient()->getIdentifier();
        $client = Passport::clientModel()::query()->find($clientId);

        if ($client === null) {
            return [];
        }

        $authCodeId = $this->nonceStore->currentAuthCodeId();
        $nonceData = $authCodeId !== null ? $this->nonceStore->pull($authCodeId) : null;
        $nonce = $nonceData['nonce'] ?? null;
        $authTimestamp = $nonceData['auth_time'] ?? time();
        $authTime = new DateTimeImmutable()->setTimestamp($authTimestamp);

        $now = new DateTimeImmutable;
        $lifetime = method_exists($client, 'getIdTokenLifetimeInSeconds')
            ? $client->getIdTokenLifetimeInSeconds()
            : (int) config('identity.id_token_lifetime', 3600);
        $expiresAt = $now->modify("+{$lifetime} seconds");

        $algorithm = method_exists($client, 'getIdTokenSigningAlgorithm')
            ? $client->getIdTokenSigningAlgorithm()
            : Algorithm::RS256;

        $subject = $this->subjectResolver->resolve($user, $client);

        $sid = null;

        try {
            $sid = $this->sidResolver->forCurrentRequest($user, $client);
        } catch (Throwable) {
            // sid is not critical for the token — continue without it if the request
            // context does not have a session (e.g. direct /oauth/token calls).
        }

        $claims = $this->claimAggregator->aggregate($user, $scopes);

        $context = new IdTokenContext(
            user: $user,
            client: $client,
            scopes: $scopes,
            issuedAt: $now,
            expiresAt: $expiresAt,
            authTime: $authTime,
            claims: $claims,
            nonce: $nonce,
            sid: $sid,
            subject: $subject,
            algorithm: $algorithm,
        );

        $idToken = $this->jwtIssuer->issueIdToken($context);

        $this->events->dispatch(new IdTokenIssued($context, $idToken));

        return ['id_token' => $idToken];
    }
}
