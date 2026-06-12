<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestUser;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;

class SubjectConsistencyTest extends TestCase
{
    public function test_userinfo_sub_matches_id_token_sub_for_a_pairwise_client(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
            'subject_type' => 'pairwise',
        ]);
        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);

        [$accessToken, $idToken] = $this->tokensFor($client, $user);

        $idSub = (new Parser(new JoseEncoder))->parse($idToken);
        $this->assertInstanceOf(Plain::class, $idSub);
        $pairwiseSub = $idSub->claims()->get('sub');

        // Pairwise sub must not be the raw user id, and userinfo must return the same value.
        $this->assertNotSame((string) $user->getAuthIdentifier(), $pairwiseSub);

        $userinfo = $this->withToken($accessToken)->getJson('/oauth/userinfo');
        $userinfo->assertOk();
        $userinfo->assertJsonPath('sub', $pairwiseSub);
    }

    public function test_a_client_cannot_introspect_another_clients_token(): void
    {
        $owner = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
        ]);
        $other = Client::factory()->create(['redirect_uris' => ['https://other.example.com/cb']]);
        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);

        [$accessToken] = $this->tokensFor($owner, $user);

        // A different client authenticates but introspects the owner's token.
        $response = $this->withBasicAuth((string) $other->getKey(), $other->plainSecret)
            ->postJson('/oauth/introspect', ['token' => $accessToken]);

        $response->assertOk();
        $response->assertExactJson(['active' => false]);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
        Passport::authorizationView('passport::authorize');
        $app['config']->set('identity.pairwise_salt', 'test-salt-123');
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();
        $this->artisan('passport:keys', ['--force' => true])->run();
    }

    /**
     * @return array{0: string, 1: string} [accessToken, idToken]
     */
    private function tokensFor(Client $client, TestUser $user): array
    {
        $auth = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));
        parse_str((string) parse_url((string) $auth->headers->get('Location'), PHP_URL_QUERY), $params);

        $json = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ])->json();

        return [$json['access_token'], $json['id_token']];
    }
}
