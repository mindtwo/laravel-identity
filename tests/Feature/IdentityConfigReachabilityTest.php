<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Identity;
use Chiiya\LaravelIdentity\Jwt\Algorithm;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestUser;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;

class IdentityConfigReachabilityTest extends TestCase
{
    public function test_default_signing_algorithm_is_used_when_client_has_no_override(): void
    {
        Identity::signingAlgorithm(Algorithm::RS384);

        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
        ]);
        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);

        $idToken = $this->authorizeFlowIdToken($client, $user);
        $this->assertNotNull($idToken);

        $parsed = (new Parser(new JoseEncoder))->parse($idToken);
        $this->assertInstanceOf(Plain::class, $parsed);
        $this->assertSame('RS384', $parsed->headers()->get('alg'));
    }

    public function test_first_party_resolver_makes_a_client_skip_consent(): void
    {
        // Not first-party by its column, so without the resolver consent would show.
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => false,
        ]);
        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);

        Identity::firstPartyClientResolver(fn (Client $c): bool => true);

        $response = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));

        // Auto-approved: redirected back with a code instead of rendering consent.
        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $params);
        $this->assertArrayHasKey('code', $params);
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

    private function authorizeFlowIdToken(Client $client, TestUser $user): ?string
    {
        $authResponse = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));

        if (! $authResponse->isRedirect()) {
            return null;
        }

        parse_str((string) parse_url((string) $authResponse->headers->get('Location'), PHP_URL_QUERY), $params);

        if (! isset($params['code'])) {
            return null;
        }

        return $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ])->json('id_token');
    }
}
