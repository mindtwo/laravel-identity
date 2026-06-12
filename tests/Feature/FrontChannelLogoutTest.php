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

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
    }
}
