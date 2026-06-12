<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestUser;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use phpseclib3\Crypt\PublicKeyLoader;

class JwksVerificationTest extends TestCase
{
    public function test_id_token_verifies_against_the_published_jwks(): void
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

        $idToken = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $client->plainSecret,
            'redirect_uri' => 'https://app.example.com/cb',
            'code' => $params['code'],
        ])->json('id_token');

        $parsed = (new Parser(new JoseEncoder))->parse($idToken);
        $this->assertInstanceOf(Plain::class, $parsed);

        // Reconstruct the public key purely from the published JWKS, as an RP would.
        $jwk = $this->getJson('/.well-known/jwks.json')->json('keys.0');
        $this->assertSame((string) $parsed->headers()->get('kid'), $jwk['kid']);

        $pem = PublicKeyLoader::load(json_encode($jwk))->toString('PKCS8');

        $valid = (new Validator)->validate(
            $parsed,
            new SignedWith(new Sha256, InMemory::plainText($pem)),
        );

        $this->assertTrue($valid, 'id_token signature must verify against the published JWKS.');

        // An RP also matches iss by exact string against the discovery document.
        $discoveryIssuer = $this->getJson('/.well-known/openid-configuration')->json('issuer');
        $this->assertSame($discoveryIssuer, $parsed->claims()->get('iss'));
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
