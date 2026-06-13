<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc;

use Illuminate\Contracts\Container\Container;
use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Contracts\ClaimProvider;
use Mindtwo\LaravelIdentity\Contracts\ScopeRegistrar;

class ClaimAggregator
{
    public function __construct(
        private readonly Container $container,
        private readonly ScopeRegistrar $scopeRegistrar,
    ) {}

    /**
     * Collect and filter claims from all registered ClaimProviders.
     *
     * @param list<string> $scopes
     *
     * @return array<string, mixed>
     */
    public function aggregate(OAuthenticatable $user, array $scopes): array
    {
        $allowedClaims = $this->scopeRegistrar->claimsFor($scopes);
        $merged = [];

        /** @var list<ClaimProvider> $providers */
        $providers = $this->container->tagged('identity.claims');

        foreach ($providers as $provider) {
            $handles = $provider->handles();

            if (! empty($handles) && empty(array_intersect($handles, $scopes))) {
                continue;
            }

            foreach ($provider->getClaims($user, $scopes) as $name => $value) {
                // Always allow sub, nonce, auth_time, sid — they are set outside the claim map.
                if (in_array($name, ['sub', 'nonce', 'auth_time', 'sid'], strict: true)) {
                    continue;
                }

                if (in_array($name, $allowedClaims, strict: true)) {
                    $merged[$name] = $value;
                }
            }
        }

        return $merged;
    }
}
