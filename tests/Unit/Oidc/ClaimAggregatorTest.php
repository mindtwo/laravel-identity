<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Unit\Oidc;

use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Contracts\ClaimProvider;
use Mindtwo\LaravelIdentity\Oidc\ClaimAggregator;
use Mindtwo\LaravelIdentity\Oidc\Scopes\StandardScopeRegistrar;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class ClaimAggregatorTest extends TestCase
{
    public function test_only_returns_claims_allowed_by_scopes(): void
    {
        $user = new TestUser(['name' => 'Alice', 'email' => 'alice@example.com']);

        $provider = new class implements ClaimProvider {
            public function getClaims(OAuthenticatable $user, array $scopes): array
            {
                return ['name' => 'Alice', 'email' => 'alice@example.com', 'phone_number' => '123'];
            }

            public function handles(): array
            {
                return [];
            }
        };

        $this->app->tag([$provider::class], 'identity.claims');
        $this->app->bind($provider::class, fn () => $provider);

        $registrar = new StandardScopeRegistrar;
        $aggregator = new ClaimAggregator($this->app, $registrar);

        // Only email scope — should get email but not name or phone.
        $claims = $aggregator->aggregate($user, ['openid', 'email']);

        $this->assertArrayHasKey('email', $claims);
        $this->assertArrayNotHasKey('name', $claims);
        $this->assertArrayNotHasKey('phone_number', $claims);
    }

    public function test_later_providers_overwrite_earlier_ones(): void
    {
        $user = new TestUser(['name' => 'Bob', 'email' => 'bob@example.com']);

        $first = new class implements ClaimProvider {
            public function getClaims(OAuthenticatable $user, array $scopes): array
            {
                return ['email' => 'first@example.com'];
            }

            public function handles(): array
            {
                return ['email'];
            }
        };

        $second = new class implements ClaimProvider {
            public function getClaims(OAuthenticatable $user, array $scopes): array
            {
                return ['email' => 'second@example.com'];
            }

            public function handles(): array
            {
                return ['email'];
            }
        };

        $this->app->tag([$first::class, $second::class], 'identity.claims');
        $this->app->bind($first::class, fn () => $first);
        $this->app->bind($second::class, fn () => $second);

        $registrar = new StandardScopeRegistrar;
        $aggregator = new ClaimAggregator($this->app, $registrar);
        $claims = $aggregator->aggregate($user, ['openid', 'email']);

        $this->assertSame('second@example.com', $claims['email']);
    }

    public function test_scope_scoped_providers_skip_when_scope_absent(): void
    {
        $user = new TestUser(['email' => 'test@example.com']);

        $called = false;
        $provider = new class($called) implements ClaimProvider {
            public function __construct(
                private bool &$called,
            ) {}

            public function getClaims(OAuthenticatable $user, array $scopes): array
            {
                $this->called = true;

                return [];
            }

            public function handles(): array
            {
                return ['email'];
            }
        };

        $this->app->tag([$provider::class], 'identity.claims');
        $this->app->bind($provider::class, fn () => $provider);

        $registrar = new StandardScopeRegistrar;
        $aggregator = new ClaimAggregator($this->app, $registrar);
        $aggregator->aggregate($user, ['openid']); // no email scope

        $this->assertFalse($called);
    }
}
