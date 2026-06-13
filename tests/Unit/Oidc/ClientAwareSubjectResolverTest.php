<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Unit\Oidc;

use Laravel\Passport\Client;
use Mindtwo\LaravelIdentity\Oidc\SubjectResolvers\ClientAwareSubjectResolver;
use Mindtwo\LaravelIdentity\Oidc\SubjectResolvers\PairwiseSubjectResolver;
use Mindtwo\LaravelIdentity\Oidc\SubjectResolvers\PublicSubjectResolver;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class ClientAwareSubjectResolverTest extends TestCase
{
    public function test_public_client_receives_plain_identifier(): void
    {
        $user = new TestUser;
        $user->id = 42;
        $client = new TestClient;
        $client->subject_type = 'public';
        $client->redirect_uris = ['https://app.example.com/callback'];

        $this->assertSame('42', $this->resolver()->resolve($user, $client));
    }

    public function test_pairwise_client_receives_pseudonymous_identifier(): void
    {
        $user = new TestUser;
        $user->id = 42;
        $client = new TestClient;
        $client->subject_type = 'pairwise';
        $client->redirect_uris = ['https://app.example.com/callback'];

        $subject = $this->resolver()->resolve($user, $client);

        $this->assertNotSame('42', $subject);
        $this->assertSame(
            (new PairwiseSubjectResolver)->resolve($user, $client),
            $subject,
        );
    }

    public function test_defaults_to_public_when_client_has_no_oidc_metadata(): void
    {
        $user = new TestUser;
        $user->id = 42;
        $client = new Client;
        $client->redirect_uris = ['https://app.example.com/callback'];

        $this->assertSame('42', $this->resolver()->resolve($user, $client));
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('identity.pairwise_salt', 'test-salt-123');
    }

    private function resolver(): ClientAwareSubjectResolver
    {
        return new ClientAwareSubjectResolver(new PublicSubjectResolver, new PairwiseSubjectResolver);
    }
}
