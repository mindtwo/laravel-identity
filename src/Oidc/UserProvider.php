<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc;

use Illuminate\Database\Eloquent\Model;
use Laravel\Passport\Contracts\OAuthenticatable;
use RuntimeException;

class UserProvider
{
    public function findById(int|string $identifier): ?OAuthenticatable
    {
        $model = $this->resolveModel();
        $user = $model::query()->find($identifier);

        return $user instanceof OAuthenticatable ? $user : null;
    }

    /**
     * Resolve the authenticatable model class from the auth provider configuration.
     * Passport derives users from the guard's provider rather than a dedicated
     * Passport::userModel(), so we locate the first OAuthenticatable provider model.
     *
     * @return class-string<Model&OAuthenticatable>
     */
    private function resolveModel(): string
    {
        foreach ((array) config('auth.providers', []) as $provider) {
            $model = $provider['model'] ?? null;

            if (is_string($model) && is_a($model, OAuthenticatable::class, allow_string: true)) {
                // @var class-string<\Illuminate\Database\Eloquent\Model&OAuthenticatable> $model
                return $model;
            }
        }

        throw new RuntimeException('No auth provider with an OAuthenticatable Eloquent model is configured.');
    }
}
