<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class EndSessionEndpointTest extends TestCase
{
    public function test_logout_without_session_is_reachable_and_not_forced_to_login(): void
    {
        // No 'auth' middleware should intercept; with no hint we land on home.
        $response = $this->get(route('identity.end_session'));

        $response->assertRedirect('/');
    }

    public function test_logout_without_session_honors_registered_post_logout_redirect_uri(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'post_logout_redirect_uris' => ['https://app.example.com/bye'],
        ]);

        $response = $this->get(route('identity.end_session', [
            'client_id' => (string) $client->getKey(),
            'post_logout_redirect_uri' => 'https://app.example.com/bye',
            'state' => 'abc',
        ]));

        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');
        $this->assertStringStartsWith('https://app.example.com/bye', $location);
        $this->assertStringContainsString('state=abc', $location);
    }

    public function test_logout_without_session_rejects_unregistered_post_logout_redirect_uri(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'post_logout_redirect_uris' => ['https://app.example.com/bye'],
        ]);

        $response = $this->get(route('identity.end_session', [
            'client_id' => (string) $client->getKey(),
            'post_logout_redirect_uri' => 'https://evil.example.com/bye',
        ]));

        $response->assertStatus(400);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
    }
}
