<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc\Scopes;

use Chiiya\LaravelIdentity\Contracts\ScopeRegistrar;

class StandardScopeRegistrar implements ScopeRegistrar
{
    /** @var array<string, list<string>> */
    private array $map = [
        'openid' => ['sub'],
        'profile' => [
            'name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website',
            'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at',
        ],
        'email' => ['email', 'email_verified'],
        'address' => ['address'],
        'phone' => ['phone_number', 'phone_number_verified'],
    ];

    public function claimsFor(array $scopes): array
    {
        $claims = [];

        foreach ($scopes as $scope) {
            foreach ($this->map[$scope] ?? [] as $claim) {
                $claims[] = $claim;
            }
        }

        return array_values(array_unique($claims));
    }

    public function register(string $scope, array $claims): void
    {
        $existing = $this->map[$scope] ?? [];
        $this->map[$scope] = array_values(array_unique([...$existing, ...$claims]));
    }

    public function all(): array
    {
        return array_keys($this->map);
    }

    public function allClaims(): array
    {
        return array_values(array_unique(array_merge(...array_values($this->map))));
    }
}
