<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Events;

use Chiiya\LaravelIdentity\Oidc\IdTokenContext;

class IdTokenIssued
{
    public function __construct(
        public readonly IdTokenContext $context,
        public readonly string $idToken,
    ) {}
}
