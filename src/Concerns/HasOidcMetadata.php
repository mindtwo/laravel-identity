<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Concerns;

use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Oidc\SubjectType;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Scope;

/**
 * Apply this trait to your Client model (which extends Laravel\Passport\Client)
 * to gain access to OIDC-specific metadata.
 *
 * @property string|null $frontchannel_logout_uri
 * @property bool $frontchannel_logout_session_required
 * @property string|null $backchannel_logout_uri
 * @property array<int, string>|null $post_logout_redirect_uris
 * @property string|null $id_token_signed_response_alg
 * @property string|null $subject_type
 * @property string|null $sector_identifier_uri
 * @property string|null $application_type
 * @property int|null $id_token_lifetime
 * @property bool $first_party
 * @property int|null $default_max_age
 * @property bool $require_auth_time_claim
 * @property string|null $initiate_login_uri
 */
trait HasOidcMetadata
{
    public function initializeHasOidcMetadata(): void
    {
        $this->mergeCasts([
            'frontchannel_logout_session_required' => 'boolean',
            'first_party' => 'boolean',
            'require_auth_time_claim' => 'boolean',
            'post_logout_redirect_uris' => 'array',
        ]);
    }

    public function getFrontchannelLogoutUri(): ?string
    {
        return $this->frontchannel_logout_uri;
    }

    public function requiresLogoutSession(): bool
    {
        return (bool) $this->frontchannel_logout_session_required;
    }

    public function getBackchannelLogoutUri(): ?string
    {
        return $this->backchannel_logout_uri;
    }

    /**
     * @return list<string>
     */
    public function getPostLogoutRedirectUris(): array
    {
        return (array) ($this->post_logout_redirect_uris ?? []);
    }

    public function matchesPostLogoutRedirectUri(string $uri): bool
    {
        return in_array($uri, $this->getPostLogoutRedirectUris(), strict: true);
    }

    public function getIdTokenSigningAlgorithm(): Algorithm
    {
        return Algorithm::tryFrom($this->id_token_signed_response_alg ?? '') ?? Algorithm::RS256;
    }

    public function getSubjectType(): SubjectType
    {
        return SubjectType::tryFrom($this->subject_type ?? '') ?? SubjectType::Public;
    }

    public function getSectorIdentifierUri(): ?string
    {
        return $this->sector_identifier_uri;
    }

    public function getApplicationType(): string
    {
        return $this->application_type ?? 'web';
    }

    public function getIdTokenLifetimeInSeconds(): int
    {
        return $this->id_token_lifetime ?? (int) config('identity.id_token_lifetime', 3600);
    }

    public function isFirstParty(): bool
    {
        return (bool) $this->first_party;
    }

    /**
     * @param Scope[] $scopes
     */
    public function skipsAuthorization(?Authenticatable $user = null, array $scopes = []): bool
    {
        return $this->isFirstParty();
    }

    public function getDefaultMaxAge(): ?int
    {
        return $this->default_max_age !== null ? (int) $this->default_max_age : null;
    }

    public function requiresAuthTimeClaim(): bool
    {
        return (bool) $this->require_auth_time_claim;
    }

    public function getInitiateLoginUri(): ?string
    {
        return $this->initiate_login_uri;
    }
}
