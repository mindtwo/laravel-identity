<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Contracts\ScopeRegistrar;
use Mindtwo\LaravelIdentity\Tests\Fixtures\LateScopeServiceProvider;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class CustomScopeRegistrationTest extends TestCase
{
    public function test_scope_from_a_later_booting_provider_is_requestable_in_passport(): void
    {
        $scopes = Passport::scopes()->pluck('id')->all();

        $this->assertContains(LateScopeServiceProvider::SCOPE, $scopes);
    }

    public function test_scope_and_its_claims_are_advertised_in_discovery(): void
    {
        $response = $this->getJson('/.well-known/openid-configuration');

        $this->assertContains(LateScopeServiceProvider::SCOPE, $response->json('scopes_supported'));
        $this->assertContains(LateScopeServiceProvider::CLAIM, $response->json('claims_supported'));
    }

    public function test_registrar_maps_the_scope_to_its_claims_for_filtering(): void
    {
        $claims = app(ScopeRegistrar::class)->claimsFor([LateScopeServiceProvider::SCOPE]);

        $this->assertContains(LateScopeServiceProvider::CLAIM, $claims);
    }

    /**
     * Load the host-app provider AFTER laravel-identity so the test fails if scope
     * registration is coupled to provider boot order.
     *
     * @param mixed $app
     */
    protected function getPackageProviders($app): array
    {
        return [...parent::getPackageProviders($app), LateScopeServiceProvider::class];
    }
}
