<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestUser;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;

class IntrospectionEndpointTest extends TestCase
{
    public function test_active_token_returns_rfc7662_payload(): void
    {
        [$client, $accessToken] = $this->issueAccessToken();

        $response = $this->withBasicAuth((string) $client->getKey(), $client->plainSecret)
            ->postJson('/oauth/introspect', ['token' => $accessToken]);

        $response->assertOk();
        $response->assertJson([
            'active' => true,
            'client_id' => (string) $client->getKey(),
            'token_type' => 'Bearer',
        ]);
        $response->assertHeader('Cache-Control', 'no-store, private');
    }

    public function test_unknown_token_is_inactive(): void
    {
        [$client] = $this->issueAccessToken();

        $response = $this->withBasicAuth((string) $client->getKey(), $client->plainSecret)
            ->postJson('/oauth/introspect', ['token' => 'not-a-real-token']);

        $response->assertOk();
        $response->assertExactJson(['active' => false]);
    }

    public function test_requires_client_authentication(): void
    {
        [, $accessToken] = $this->issueAccessToken();

        $this->postJson('/oauth/introspect', ['token' => $accessToken])->assertStatus(401);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
        Passport::authorizationView('passport::authorize');
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();
        $this->artisan('passport:keys', ['--force' => true])->run();
    }

    /**
     * @return array{0: Client, 1: string}
     */
    private function issueAccessToken(): array
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

        $authResponse = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));

        parse_str((string) parse_url((string) $authResponse->headers->get('Location'), PHP_URL_QUERY), $params);

        $token = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ])->json('access_token');

        return [$client, $token];
    }
}
