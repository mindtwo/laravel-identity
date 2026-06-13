<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Events;

use Mindtwo\LaravelIdentity\Oidc\IdTokenContext;

class IdTokenIssued
{
    public function __construct(
        public readonly IdTokenContext $context,
        public readonly string $idToken,
    ) {}
}
