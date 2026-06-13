<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Scope;
use Mindtwo\LaravelIdentity\Identity;
use Mindtwo\LaravelIdentity\Jwt\Algorithm;
use Mindtwo\LaravelIdentity\Oidc\SubjectType;

/**
 * Apply this trait to your Client model (which extends Laravel\Passport\Client)
 * to gain access to OIDC-specific metadata.
 *
 * @property string|null $frontchannel_logout_uri
 * @property bool $frontchannel_logout_session_required
 * @property array<int, string>|null $post_logout_redirect_uris
 * @property string|null $id_token_signed_response_alg
 * @property string|null $subject_type
 * @property string|null $sector_identifier_uri
 * @property int|null $id_token_lifetime
 * @property bool $first_party
 * @property int|null $default_max_age
 */
trait HasOidcMetadata
{
    public function initializeHasOidcMetadata(): void
    {
        $this->mergeCasts([
            'frontchannel_logout_session_required' => 'boolean',
            'first_party' => 'boolean',
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
        return Algorithm::tryFrom($this->id_token_signed_response_alg ?? '') ?? Identity::$defaultSigningAlgorithm;
    }

    public function getSubjectType(): SubjectType
    {
        return SubjectType::tryFrom($this->subject_type ?? '') ?? SubjectType::Public;
    }

    public function getSectorIdentifierUri(): ?string
    {
        return $this->sector_identifier_uri;
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
        return Identity::clientIsFirstParty($this);
    }

    public function getDefaultMaxAge(): ?int
    {
        return $this->default_max_age !== null ? (int) $this->default_max_age : null;
    }
}
