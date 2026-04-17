<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Events;

use Laravel\Passport\Contracts\OAuthenticatable;

class UserLoggedOut
{
    public function __construct(
        public readonly OAuthenticatable $user,
        /** The client that initiated the logout, or null for local logout. */
        public readonly ?\Laravel\Passport\Client $initiatingClient,
    ) {}
}
