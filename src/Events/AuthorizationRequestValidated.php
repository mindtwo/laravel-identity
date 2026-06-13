<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Events;

use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Oidc\AuthRequestContext;

class AuthorizationRequestValidated
{
    public function __construct(
        public readonly OAuthenticatable $user,
        public readonly Client $client,
        public readonly AuthRequestContext $context,
    ) {}
}
