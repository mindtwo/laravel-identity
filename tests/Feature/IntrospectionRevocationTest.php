<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class IntrospectionRevocationTest extends TestCase
{
    public function test_revoked_token_is_reported_inactive(): void
    {
        [$client, $accessToken] = $this->issueToken();

        Passport::token()->newQuery()->whereKey($this->jti($accessToken))->update(['revoked' => true]);

        $response = $this->withBasicAuth((string) $client->getKey(), $client->plainSecret)
            ->postJson('/oauth/introspect', ['token' => $accessToken]);

        $response->assertOk();
        $response->assertExactJson(['active' => false]);
    }

    public function test_expired_token_is_reported_inactive(): void
    {
        [$client, $accessToken] = $this->issueToken();

        Passport::token()->newQuery()->whereKey($this->jti($accessToken))
            ->update(['expires_at' => now()->subMinute()]);

        $response = $this->withBasicAuth((string) $client->getKey(), $client->plainSecret)
            ->postJson('/oauth/introspect', ['token' => $accessToken]);

        $response->assertOk();
        $response->assertExactJson(['active' => false]);
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
    private function issueToken(): array
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
        ]);
        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);

        $auth = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));
        parse_str((string) parse_url((string) $auth->headers->get('Location'), PHP_URL_QUERY), $params);

        $accessToken = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ])->json('access_token');

        return [$client, $accessToken];
    }

    private function jti(string $accessToken): string
    {
        $parsed = (new Parser(new JoseEncoder))->parse($accessToken);
        \assert($parsed instanceof Plain);

        return (string) $parsed->claims()->get(RegisteredClaims::ID);
    }
}
