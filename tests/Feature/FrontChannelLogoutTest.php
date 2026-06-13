<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Illuminate\Support\Facades\Blade;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Session\OidcSession;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

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

    public function test_front_channel_logout_component_is_embeddable(): void
    {
        // Apps can drop the mechanism into their own page without reimplementing it.
        $html = Blade::render(
            '<x-identity::front-channel-logout :urls="$urls" redirect="/done" />',
            ['urls' => ['https://a.example.com/fc', 'https://b.example.com/fc']],
        );

        $this->assertStringContainsString('https://a.example.com/fc', $html);
        $this->assertStringContainsString('https://b.example.com/fc', $html);
        $this->assertStringContainsString('<iframe', $html);
        $this->assertStringContainsString('/done', $html);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
    }
}
