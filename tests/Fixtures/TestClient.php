<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Fixtures;

use Laravel\Passport\Client;
use Mindtwo\LaravelIdentity\Concerns\HasOidcMetadata;

class TestClient extends Client
{
    use HasOidcMetadata;
}
