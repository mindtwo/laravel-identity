<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Events;

use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

class UserLoggedOut
{
    public function __construct(
        public readonly OAuthenticatable $user,
        /** The client that initiated the logout, or null for local logout. */
        public readonly ?Client $initiatingClient,
    ) {}
}
