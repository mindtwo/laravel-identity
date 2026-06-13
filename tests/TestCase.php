<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Laravel\Passport\PassportServiceProvider;
use Mindtwo\LaravelIdentity\Identity;
use Mindtwo\LaravelIdentity\LaravelIdentityServiceProvider;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Identity::reset();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'Mindtwo\LaravelIdentity\Tests\Factories\\'.class_basename($modelName).'Factory',
        );
    }

    protected function getPackageProviders($app): array
    {
        return [
            PassportServiceProvider::class,
            LaravelIdentityServiceProvider::class,
        ];
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadLaravelMigrations();
        $this->loadMigrationsFrom(__DIR__.'/../vendor/laravel/passport/database/migrations');
        $this->artisan('migrate', ['--database' => 'testing'])->run();

        // The package ships its migrations as `.php.stub` files intended for
        // publishing (they alter Passport's tables). Laravel's migrator skips
        // `.stub` files, so apply them directly here once the base tables exist.
        foreach (glob(__DIR__.'/../database/migrations/*.php.stub') ?: [] as $stub) {
            (require $stub)->up();
        }
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('auth.guards.api', [
            'driver' => 'passport',
            'provider' => 'users',
        ]);
        $app['config']->set('auth.providers.users', [
            'driver' => 'eloquent',
            'model' => TestUser::class,
        ]);
    }
}
