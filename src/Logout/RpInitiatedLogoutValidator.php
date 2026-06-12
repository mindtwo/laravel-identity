<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Logout;

use Chiiya\LaravelIdentity\Exceptions\InvalidIdTokenHint;
use Chiiya\LaravelIdentity\Exceptions\InvalidRpLogoutRequest;
use Chiiya\LaravelIdentity\Identity;
use Chiiya\LaravelIdentity\Jwt\JwtValidator;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;

class RpInitiatedLogoutValidator
{
    public function __construct(
        private readonly JwtValidator $jwtValidator,
    ) {}

    /**
     * Validate an RP-Initiated Logout request.
     *
     * @throws InvalidRpLogoutRequest
     */
    public function validate(
        ?string $idTokenHint,
        ?string $postLogoutRedirectUri,
        ?string $state,
        ?string $clientIdParam,
    ): LogoutRequest {
        if (empty($idTokenHint) && empty($clientIdParam)) {
            throw new InvalidRpLogoutRequest('Either id_token_hint or client_id is required.');
        }

        if (! empty($idTokenHint)) {
            return $this->validateWithToken($idTokenHint, $postLogoutRedirectUri, $state, $clientIdParam);
        }

        return $this->validateWithClientId((string) $clientIdParam, $postLogoutRedirectUri, $state);
    }

    /**
     * @throws InvalidRpLogoutRequest
     */
    private function validateWithToken(
        string $idTokenHint,
        ?string $postLogoutRedirectUri,
        ?string $state,
        ?string $clientIdParam,
    ): LogoutRequest {
        try {
            $token = $this->jwtValidator->parseAndVerify($idTokenHint);
        } catch (InvalidIdTokenHint $e) {
            throw new InvalidRpLogoutRequest('Invalid id_token_hint: '.$e->getMessage(), $e->getCode(), previous: $e);
        }

        $issuer = Identity::issuer();

        if ($token->claims()->get('iss') !== $issuer) {
            throw new InvalidRpLogoutRequest('id_token_hint was not issued by this server.');
        }

        $claims = $token->claims();
        $sub = $claims->get('sub');
        $aud = $claims->get('aud');
        $exp = $claims->get('exp');

        if (empty($sub)) {
            throw new InvalidRpLogoutRequest('id_token_hint is missing sub claim.');
        }

        // Allow logout tokens up to 30 days after expiry — users may present stale tokens.
        if ($exp !== null) {
            $maxAge = now()->subDays(30)->timestamp;

            if ($exp->getTimestamp() < $maxAge) {
                throw new InvalidRpLogoutRequest('id_token_hint has expired beyond the allowed tolerance.');
            }
        }

        // Resolve client from aud or client_id param.
        $clientId = $clientIdParam;

        if ($clientId === null) {
            $clientId = is_array($aud) ? ($aud[0] ?? null) : $aud;
        }

        if (empty($clientId)) {
            throw new InvalidRpLogoutRequest('Cannot determine client from id_token_hint.');
        }

        $client = Passport::clientModel()::query()->find($clientId);

        if ($client === null) {
            throw new InvalidRpLogoutRequest("Unknown client: {$clientId}");
        }

        $resolvedRedirectUri = $this->resolveRedirectUri($client, $postLogoutRedirectUri);

        return new LogoutRequest(
            client: $client,
            subject: (string) $sub,
            postLogoutRedirectUri: $resolvedRedirectUri,
            state: $state,
        );
    }

    /**
     * @throws InvalidRpLogoutRequest
     */
    private function validateWithClientId(
        string $clientId,
        ?string $postLogoutRedirectUri,
        ?string $state,
    ): LogoutRequest {
        $client = Passport::clientModel()::query()->find($clientId);

        if ($client === null) {
            throw new InvalidRpLogoutRequest("Unknown client: {$clientId}");
        }

        $resolvedRedirectUri = $this->resolveRedirectUri($client, $postLogoutRedirectUri);

        return new LogoutRequest(
            client: $client,
            subject: '',
            postLogoutRedirectUri: $resolvedRedirectUri,
            state: $state,
        );
    }

    private function resolveRedirectUri(Client $client, ?string $requested): ?string
    {
        if ($requested === null) {
            return null;
        }

        // Fail closed: the URI must be verifiable against the client's registered
        // post_logout_redirect_uris. A client model without that capability (e.g.
        // missing the HasOidcMetadata trait) cannot register any, so every URI is
        // rejected rather than blindly honored — preventing an open redirect
        // (RP-Initiated Logout 1.0 §3).
        if (! method_exists($client, 'matchesPostLogoutRedirectUri')
            || ! $client->matchesPostLogoutRedirectUri($requested)) {
            throw new InvalidRpLogoutRequest('post_logout_redirect_uri is not registered for this client.');
        }

        return $requested;
    }
}
