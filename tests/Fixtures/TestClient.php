<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Fixtures;

use Chiiya\LaravelIdentity\Concerns\HasOidcMetadata;
use Laravel\Passport\Client;

class TestClient extends Client
{
    use HasOidcMetadata;
}
