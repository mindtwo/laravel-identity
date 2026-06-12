<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Session\OidcSession;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestUser;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;

class FrontChannelLogoutTest extends TestCase
{
    public function test_logout_renders_front_channel_iframes_for_relevant_clients(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
            'frontchannel_logout_uri' => 'https://app.example.com/frontchannel-logout',
        ]);

        $user = TestUser::query()->create([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => bcrypt('secret'),
        ]);

        OidcSession::query()->create([
            'user_id' => $user->getAuthIdentifier(),
            'client_id' => (string) $client->getKey(),
            'laravel_session_id' => 'sess-1',
            'created_at' => now(),
            'last_seen_at' => now(),
        ]);

        $response = $this->actingAs($user)->post(route('identity.end_session'), [
            'client_id' => (string) $client->getKey(),
        ]);

        $response->assertOk();
        $response->assertSee('https://app.example.com/frontchannel-logout', escape: false);
        $response->assertSee('<iframe', escape: false);
    }

    public function test_frontchannel_logout_endpoint_rejects_external_redirect(): void
    {
        $user = TestUser::query()->create([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => bcrypt('secret'),
        ]);

        // An attacker-supplied absolute URL must not become the redirect target.
        $response = $this->actingAs($user)->get(
            route('identity.frontchannel_logout', ['redirect' => 'https://evil.example.com/phish']),
        );

        $response->assertOk();
        $response->assertDontSee('evil.example.com');
    }

    public function test_frontchannel_logout_endpoint_allows_local_redirect(): void
    {
        $user = TestUser::query()->create([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => bcrypt('secret'),
        ]);

        $response = $this->actingAs($user)->get(
            route('identity.frontchannel_logout', ['redirect' => '/dashboard']),
        );

        $response->assertOk();
        $response->assertSee('/dashboard', escape: false);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
    }
}
