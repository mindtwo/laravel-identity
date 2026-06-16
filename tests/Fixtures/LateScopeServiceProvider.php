<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Fixtures;

use Illuminate\Support\ServiceProvider;
use Mindtwo\LaravelIdentity\Identity;

/**
 * A host-app-style provider that registers a custom scope from boot(). When
 * loaded after LaravelIdentityServiceProvider it proves scope registration is
 * order-independent.
 */
class LateScopeServiceProvider extends ServiceProvider
{
    public const SCOPE = 'org';
    public const CLAIM = 'https://auth.example.com/department';

    public function boot(): void
    {
        Identity::registerScope(self::SCOPE, [self::CLAIM]);
    }
}
