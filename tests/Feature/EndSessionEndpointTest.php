<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
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

    public function test_logout_clears_the_remember_me_cookie(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
        ]);

        $user = TestUser::query()->create([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => bcrypt('secret'),
        ]);
        $user->forceFill(['remember_token' => 'remember-me'])->save();

        $recaller = Auth::guard()->getRecallerName();

        // Authenticated by the recaller cookie alone, like a returning browser.
        $response = $this
            ->withCookie($recaller, $user->getAuthIdentifier().'|remember-me|'.$user->getAuthPassword())
            ->get(route('identity.end_session', ['client_id' => (string) $client->getKey()]));

        $response->assertRedirect();
        $response->assertCookieExpired($recaller);
        $this->assertNotSame('remember-me', $user->fresh()?->remember_token);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
    }
}
