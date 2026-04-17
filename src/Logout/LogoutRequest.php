<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Logout;

use Laravel\Passport\Client;

readonly class LogoutRequest
{
    public function __construct(
        public Client $client,
        public string $subject,
        public ?string $postLogoutRedirectUri,
        public ?string $state,
    ) {}
}
