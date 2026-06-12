<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;

class AuthorizeEndpointTest extends TestCase
{
    public function test_prompt_none_for_guest_redirects_login_required_to_registered_uri(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
        ]);

        $response = $this->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'xyz',
            'prompt' => 'none',
        ]));

        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');
        $this->assertStringStartsWith('https://app.example.com/cb', $location);
        $this->assertStringContainsString('error=login_required', $location);
    }

    public function test_unregistered_redirect_uri_is_never_redirected_to(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
        ]);

        $response = $this->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://evil.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
            'prompt' => 'none',
        ]));

        $this->assertStringNotContainsString('evil.example.com', (string) $response->headers->get('Location'));
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::authorizationView('passport::authorize');
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();
        $this->artisan('passport:keys', ['--force' => true])->run();
    }
}
