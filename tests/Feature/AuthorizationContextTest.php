<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use DateTimeImmutable;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Mindtwo\LaravelIdentity\Oidc\NonceStore;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class AuthorizationContextTest extends TestCase
{
    public function test_missing_authorization_context_is_rejected_and_previous_refresh_still_works(): void
    {
        $client = $this->createClient();
        $initial = $this->exchange($client, $this->codeFrom($this->authorize($client, 'original')));
        $claims = $this->claims($initial);
        $code = $this->codeFrom($this->authorize($client, 'lost'));
        app('cache')->flush();

        $this->exchange($client, $code)->assertStatus(500)
            ->assertJsonPath('error', 'server_error')
            ->assertJsonMissingPath('id_token')->assertJsonMissingPath('access_token');

        $refreshed = $this->claims($this->refresh($client, $initial->json('refresh_token')));
        $this->assertSame($claims->get('auth_time'), $refreshed->get('auth_time'));
        $this->assertSame($claims->get('sid'), $refreshed->get('sid'));
        $this->assertFalse($refreshed->has('nonce'));
    }

    public function test_context_without_auth_time_is_rejected(): void
    {
        $client = $this->createClient();
        $code = $this->codeFrom($this->authorize($client, 'incomplete'));
        $key = 'identity:nonce:'.Passport::authCode()->sole()->getKey();
        $context = app('cache')->get($key);
        $this->assertIsArray($context);
        unset($context['auth_time']);
        app('cache')->put($key, $context, 600);

        $this->exchange($client, $code)->assertStatus(500)
            ->assertJsonPath('error', 'server_error')
            ->assertJsonMissingPath('id_token')->assertJsonMissingPath('access_token');
    }

    public function test_refresh_after_code_exchange_resets_the_shared_code_marker(): void
    {
        $client = $this->createClient();
        $store = app(NonceStore::class);
        $initial = $this->exchange($client, $this->codeFrom($this->authorize($client, 'original')));
        $claims = $this->claims($initial);
        $this->assertSame('original', $claims->get('nonce'));
        $refreshed = $this->claims($this->refresh($client, $initial->json('refresh_token')));

        $this->assertSame($store, app(NonceStore::class));
        $this->assertNull($store->currentAuthCodeId());
        $this->assertSame($claims->get('auth_time'), $refreshed->get('auth_time'));
        $this->assertSame($claims->get('sid'), $refreshed->get('sid'));
        $this->assertFalse($refreshed->has('nonce'));
    }

    public function test_authorization_without_nonce_remains_valid(): void
    {
        $client = $this->createClient();
        $code = $this->codeFrom($this->authorize($client, '', ['nonce' => null]));
        $claims = $this->claims($this->exchange($client, $code));
        $this->assertFalse($claims->has('nonce'));
        $this->assertNotNull($claims->get('auth_time'));
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
        Passport::authorizationView('passport::authorize');
        $app['config']->set('cache.default', 'array');
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();
        $this->artisan('passport:keys', ['--force' => true])->run();
    }

    private function createClient(bool $firstParty = true): Client
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => $firstParty,
        ]);
        $user = TestUser::query()->create([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => bcrypt('secret'),
        ]);
        $user->setAuthTime(new DateTimeImmutable('2026-01-02T03:04:05Z'));
        $this->actingAs($user);

        return $client;
    }

    private function authorize(Client $client, string $nonce, array $overrides = []): TestResponse
    {
        return $this->get(route('passport.authorizations.authorize', array_replace([
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
            'nonce' => $nonce,
        ], $overrides)));
    }

    private function codeFrom(TestResponse $response): string
    {
        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $params);
        $this->assertArrayHasKey('code', $params);

        return $params['code'];
    }

    private function exchange(Client $client, string $code): TestResponse
    {
        return $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $code,
        ]);
    }

    private function refresh(Client $client, string $refreshToken): TestResponse
    {
        return $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'refresh_token' => $refreshToken,
        ]);
    }

    private function claims(TestResponse $response): DataSet
    {
        $response->assertOk();
        $token = (new Parser(new JoseEncoder))->parse($response->json('id_token'));
        $this->assertInstanceOf(Plain::class, $token);

        return $token->claims();
    }
}
