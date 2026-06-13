<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Mindtwo\LaravelIdentity\Oidc\SubjectType;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

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
