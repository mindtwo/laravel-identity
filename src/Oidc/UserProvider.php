<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Passport;
use RuntimeException;

class UserProvider
{
    public function findById(int|string $identifier): ?OAuthenticatable
    {
        $model = Passport::userModel();

        if ($model === null) {
            throw new RuntimeException('Cannot resolve user model. Ensure Passport is configured.');
        }

        // @var OAuthenticatable|null
        return $model::find($identifier);
    }
}
