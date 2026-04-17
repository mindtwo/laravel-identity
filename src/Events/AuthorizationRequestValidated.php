<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Events;

use Chiiya\LaravelIdentity\Oidc\AuthRequestContext;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

class AuthorizationRequestValidated
{
    public function __construct(
        public readonly OAuthenticatable $user,
        public readonly Client $client,
        public readonly AuthRequestContext $context,
    ) {}
}
