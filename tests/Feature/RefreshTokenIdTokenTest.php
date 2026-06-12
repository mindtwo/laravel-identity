<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestUser;
use Chiiya\LaravelIdentity\Tests\TestCase;
use DateTimeImmutable;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;

class RefreshTokenIdTokenTest extends TestCase
{
    public function test_refreshing_an_openid_token_reissues_an_id_token(): void
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

        $refreshToken = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ])->json('refresh_token');

        $this->assertNotNull($refreshToken);

        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'scope' => 'openid',
        ]);

        $refreshed->assertOk();
        $idToken = $refreshed->json('id_token');
        $this->assertNotNull($idToken, 'Refreshed response should include a new id_token.');

        $parsed = (new Parser(new JoseEncoder))->parse($idToken);
        $this->assertInstanceOf(Plain::class, $parsed);
        $this->assertSame((string) $user->getAuthIdentifier(), $parsed->claims()->get('sub'));
    }

    public function test_refreshed_id_token_preserves_original_auth_time_and_sid(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
            'frontchannel_logout_uri' => 'https://app.example.com/fc-logout',
            'frontchannel_logout_session_required' => true,
        ]);

        $user = TestUser::query()->create([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => bcrypt('secret'),
        ]);

        // Pin the original authentication moment to a fixed point in the past.
        $originalAuthTime = new DateTimeImmutable('2020-01-02T03:04:05+00:00');
        $user->setAuthTime($originalAuthTime);

        $authResponse = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));

        parse_str((string) parse_url((string) $authResponse->headers->get('Location'), PHP_URL_QUERY), $params);

        $initial = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ]);

        $initialClaims = (new Parser(new JoseEncoder))->parse($initial->json('id_token'))->claims();
        $this->assertSame($originalAuthTime->getTimestamp(), $initialClaims->get('auth_time'));
        $originalSid = $initialClaims->get('sid');
        $this->assertNotEmpty($originalSid);

        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $initial->json('refresh_token'),
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'scope' => 'openid',
        ]);

        $refreshedClaims = (new Parser(new JoseEncoder))->parse($refreshed->json('id_token'))->claims();

        // Core 1.0 §12.2: auth_time MUST be the original authentication time, and
        // the session identifier MUST stay correlated for front-channel logout.
        $this->assertSame(
            $originalAuthTime->getTimestamp(),
            $refreshedClaims->get('auth_time'),
            'Refreshed id_token must preserve the original auth_time.',
        );
        $this->assertSame($originalSid, $refreshedClaims->get('sid'));
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
