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

class FrontChannelSidCorrelationTest extends TestCase
{
    public function test_id_token_sid_matches_the_front_channel_logout_iframe_sid(): void
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

        $authResponse = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));

        parse_str((string) parse_url((string) $authResponse->headers->get('Location'), PHP_URL_QUERY), $params);

        $idToken = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ])->json('id_token');

        $parsed = (new Parser(new JoseEncoder))->parse($idToken);
        $this->assertInstanceOf(Plain::class, $parsed);
        $sid = $parsed->claims()->get('sid');
        $this->assertNotEmpty($sid, 'id_token should carry a sid for a session-aware client.');

        // Logout in the same browser session must emit an iframe carrying that sid.
        $logout = $this->actingAs($user)->post(route('identity.end_session'), [
            'client_id' => (string) $client->getKey(),
        ]);

        $logout->assertOk();
        $logout->assertSee('sid='.$sid, escape: false);
        $logout->assertSee('iss=', escape: false);
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
