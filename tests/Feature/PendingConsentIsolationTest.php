<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use DateTimeImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Mindtwo\LaravelIdentity\Events\AuthorizationRequestValidated;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;
use PHPUnit\Framework\Attributes\TestWith;

class PendingConsentIsolationTest extends TestCase
{
    #[TestWith([['redirect_uri' => 'https://invalid.example/cb']])]
    #[TestWith([['client_id' => 'missing-client']])]
    #[TestWith([['scope' => 'unknown-scope']])]
    #[TestWith([['response_type' => 'unsupported']])]
    #[TestWith([['code_challenge' => 'too-short', 'code_challenge_method' => 'S256']])]
    #[TestWith([['code_challenge' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'code_challenge_method' => 'unknown']])]
    #[TestWith([['redirect_uri' => 'https://invalid.example/cb', 'max_age' => 0, 'prompt' => 'login']])]
    public function test_invalid_request_preserves_previous_pending_consent(array $overrides): void
    {
        $client = $this->createClient(false);
        $validated = 0;
        app(Dispatcher::class)->listen(AuthorizationRequestValidated::class, function () use (&$validated): void {
            ++$validated;
        });
        $token = $this->pending($client, 'nonce-A');
        $this->assertSame(1, $validated);
        $pendingRequest = session('authRequest');
        $context = session('identity.oidc_auth');

        $response = $this->authorize($client, 'nonce-B', $overrides);

        if ($response->isRedirect()) {
            parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $error);
            $this->assertArrayHasKey('error', $error);
            $this->assertArrayNotHasKey('code', $error);
        } else {
            $this->assertContains($response->getStatusCode(), [400, 401]);
            $response->assertJsonStructure(['error']);
        }

        $this->assertAuthenticated();
        $this->assertSame($token, session('authToken'));
        $this->assertSame($pendingRequest, session('authRequest'));
        $this->assertSame($context, session('identity.oidc_auth'));
        $this->assertSame(1, $validated);
        $this->assertSame(0, Passport::authCode()->count());

        $initial = $this->exchange($client, $this->codeFrom($this->approve($token)));
        $claims = $this->claims($initial);
        $this->assertSame('nonce-A', $claims->get('nonce'));
        $this->assertSame($context['auth_time'], $claims->get('auth_time'));
        $this->assertSame($context['sid'], $claims->get('sid'));
        $refreshed = $this->claims($this->refresh($client, $initial->json('refresh_token')));
        $this->assertSame($claims->get('sid'), $refreshed->get('sid'));
        $this->assertSame($claims->get('auth_time'), $refreshed->get('auth_time'));
        $this->assertFalse($refreshed->has('nonce'));
    }

    public function test_valid_request_requiring_consent_still_supersedes_previous_consent(): void
    {
        $client = $this->createClient(false);
        $token = $this->pending($client, 'nonce-A');
        $response = $this->authorize($client, 'nonce-B', ['prompt' => 'none']);
        $response->assertRedirect();
        $this->assertStringContainsString('error=consent_required', $response->headers->get('Location'));
        $this->approve($token)->assertForbidden();
        $this->assertSame(0, Passport::authCode()->count());
    }

    public function test_valid_request_requiring_reauthentication_does_not_restore_old_consent(): void
    {
        $client = $this->createClient(false);
        $token = $this->pending($client, 'nonce-A');
        $response = $this->authorize($client, 'nonce-B', ['prompt' => 'none', 'max_age' => 0]);
        $response->assertRedirect();
        $this->assertStringContainsString('error=login_required', $response->headers->get('Location'));
        $this->assertGuest();
        $this->assertNull(session('authToken'));
        $this->assertNull(session('authRequest'));
        $this->assertNull(session('identity.oidc_auth'));
        $this->assertSame(0, Passport::authCode()->count());
    }

    public function test_valid_pkce_authorization_can_be_exchanged(): void
    {
        $client = $this->createClient();
        $validated = 0;
        app(Dispatcher::class)->listen(AuthorizationRequestValidated::class, function () use (&$validated): void {
            ++$validated;
        });
        $previous = $this->pending($client, 'nonce-A');
        $this->assertSame(1, $validated);
        $verifier = str_repeat('v', 64);
        $challenge = mb_rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $code = $this->codeFrom($this->authorize($client, 'nonce-B', [
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
        $this->assertSame(2, $validated);
        $this->approve($previous)->assertForbidden();

        $response = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $code,
            'code_verifier' => $verifier,
        ]);
        $this->assertSame('nonce-B', $this->claims($response)->get('nonce'));
    }

    public function test_failure_after_initial_validation_does_not_restore_old_consent(): void
    {
        $client = $this->createClient(false);
        // Simulate a client becoming unavailable between the two validations.
        app(Dispatcher::class)->listen(AuthorizationRequestValidated::class, function (AuthorizationRequestValidated $event): void {
            if ($event->context->nonce === 'nonce-B') {
                $event->client->forceFill(['revoked' => true])->save();
            }
        });
        $previous = $this->pending($client, 'nonce-A');
        $next = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
        ]);
        $this->authorize($next, 'nonce-B')->assertStatus(401);
        $this->assertNull(session('authToken'));
        $this->assertNull(session('authRequest'));
        $this->approve($previous)->assertForbidden();
        $this->assertSame(0, Passport::authCode()->count());
    }

    public function test_automatic_authorization_supersedes_pending_consent(): void
    {
        $client = $this->createClient();
        $token = $this->pending($client, 'nonce-A');
        $code = $this->codeFrom($this->authorize($client, 'nonce-B'));

        $this->approve($token)->assertForbidden();
        $this->assertSame(1, Passport::authCode()->count());
        $this->assertSame('nonce-B', $this->claims($this->exchange($client, $code))->get('nonce'));
    }

    public function test_latest_explicit_consent_preserves_nonce_and_refresh(): void
    {
        $client = $this->createClient(false);
        $previous = $this->pending($client, 'nonce-A');
        $current = $this->pending($client, 'nonce-B');
        $this->assertNotSame($previous, $current);
        $initial = $this->exchange($client, $this->codeFrom($this->approve($current)));
        $claims = $this->claims($initial);
        $this->assertSame('nonce-B', $claims->get('nonce'));

        $this->approve($previous)->assertForbidden();
        $this->assertSame(1, Passport::authCode()->count());
        $refreshed = $this->claims($this->refresh($client, $initial->json('refresh_token')));
        $this->assertSame($claims->get('sid'), $refreshed->get('sid'));
        $this->assertSame($claims->get('auth_time'), $refreshed->get('auth_time'));
        $this->assertFalse($refreshed->has('nonce'));
    }

    public function test_denied_consent_does_not_contaminate_next_authorization(): void
    {
        $client = $this->createClient(false);
        $token = $this->pending($client, 'nonce-A');
        $response = $this->delete(route('passport.authorizations.deny'), ['auth_token' => $token]);
        $response->assertRedirect();
        $this->assertStringContainsString('error=access_denied', $response->headers->get('Location'));
        $this->assertSame(0, Passport::authCode()->count());

        $next = $this->pending($client, 'nonce-B');
        $claims = $this->claims($this->exchange($client, $this->codeFrom($this->approve($next))));
        $this->assertSame('nonce-B', $claims->get('nonce'));
    }

    protected function setUp(): void
    {
        parent::setUp();
        app('view')->addNamespace('identity-regression', __DIR__.'/../Fixtures/views');
        Passport::authorizationView('identity-regression::consent');
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

    private function pending(Client $client, string $nonce): string
    {
        $this->authorize($client, $nonce, ['prompt' => 'consent'])->assertOk();
        $token = session('authToken');
        $this->assertIsString($token);
        $this->assertNotSame('', $token);

        return $token;
    }

    private function approve(string $token): TestResponse
    {
        return $this->post(route('passport.authorizations.approve'), ['auth_token' => $token]);
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
