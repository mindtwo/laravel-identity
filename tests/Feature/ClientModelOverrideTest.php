<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Chiiya\LaravelIdentity\Oidc\SubjectType;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestClient;
use Chiiya\LaravelIdentity\Tests\Fixtures\TestUser;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;

class ClientModelOverrideTest extends TestCase
{
    public function test_oidc_metadata_round_trips_through_overridden_client_model(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/callback'],
            'subject_type' => 'pairwise',
            'id_token_signed_response_alg' => 'RS512',
        ]);

        $reloaded = Passport::clientModel()::query()->find($client->getKey());

        $this->assertInstanceOf(TestClient::class, $reloaded);
        $this->assertSame(SubjectType::Pairwise, $reloaded->getSubjectType());
        $this->assertSame('RS512', $reloaded->getIdTokenSigningAlgorithm()->value);
    }

    public function test_subject_resolver_reaches_pairwise_for_overridden_model(): void
    {
        $created = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/callback'],
            'subject_type' => 'pairwise',
        ]);
        $client = Passport::clientModel()::query()->find($created->getKey());

        $user = new TestUser;
        $user->id = 7;

        /** @var SubjectIdentifierResolver $resolver */
        $resolver = $this->app->make(SubjectIdentifierResolver::class);

        $this->assertNotSame('7', $resolver->resolve($user, $client));
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('identity.pairwise_salt', 'test-salt-123');
        Passport::useClientModel(TestClient::class);
    }
}
