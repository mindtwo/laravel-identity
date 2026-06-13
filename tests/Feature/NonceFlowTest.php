<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class NonceFlowTest extends TestCase
{
    public function test_nonce_from_authorization_request_is_embedded_in_id_token(): void
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

        // First-party client skips the consent screen and issues a code immediately.
        $authResponse = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'xyz',
            'nonce' => 'n-0S6_WzA2Mj',
        ]));

        $authResponse->assertRedirect();
        parse_str((string) parse_url((string) $authResponse->headers->get('Location'), PHP_URL_QUERY), $params);
        $this->assertArrayHasKey('code', $params);

        $tokenResponse = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ]);

        $tokenResponse->assertOk();
        $idToken = $tokenResponse->json('id_token');
        $this->assertNotNull($idToken, 'Response did not include an id_token.');

        $parsed = (new Parser(new JoseEncoder))->parse($idToken);
        $this->assertInstanceOf(Plain::class, $parsed);
        $this->assertSame('n-0S6_WzA2Mj', $parsed->claims()->get('nonce'));
        $this->assertSame((string) $user->getAuthIdentifier(), $parsed->claims()->get('sub'));
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
}
