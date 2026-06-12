<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Discovery;

use Chiiya\LaravelIdentity\Contracts\DiscoveryDocumentBuilder;
use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Contracts\ScopeRegistrar;

class DefaultDiscoveryBuilder implements DiscoveryDocumentBuilder
{
    public function __construct(
        private readonly KeyResolver $keyResolver,
        private readonly ScopeRegistrar $scopeRegistrar,
    ) {}

    public function build(): array
    {
        $issuer = config('identity.issuer') ?: config('app.url');

        // Drop only absent (null) values — false booleans like
        // *_parameter_supported must remain in the document.
        return array_filter([
            'issuer' => $issuer,
            'authorization_endpoint' => route('passport.authorizations.authorize'),
            'token_endpoint' => route('passport.token'),
            'userinfo_endpoint' => route('identity.userinfo'),
            'jwks_uri' => route('identity.jwks'),
            'end_session_endpoint' => route('identity.end_session'),
            'introspection_endpoint' => route('identity.introspect'),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public', 'pairwise'],
            'id_token_signing_alg_values_supported' => $this->keyResolver->supportedAlgs(),
            'scopes_supported' => $this->scopeRegistrar->all(),
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            // Scope-mapped claims plus the always-emitted id_token claims that are
            // not tied to a scope (Discovery 1.0 §3; list is non-exhaustive).
            'claims_supported' => array_values(array_unique([
                'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time',
                ...$this->scopeRegistrar->allClaims(),
            ])),
            'code_challenge_methods_supported' => ['S256'],
            'request_parameter_supported' => false,
            // Defaults to true per Discovery 1.0; advertised explicitly since this OP
            // does not accept the request_uri parameter.
            'request_uri_parameter_supported' => false,
            'claims_parameter_supported' => false,
            'frontchannel_logout_supported' => true,
            'frontchannel_logout_session_supported' => true,
        ], static fn ($value): bool => $value !== null);
    }
}
