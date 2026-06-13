<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Unit\Oidc;

use Laravel\Passport\Client;
use Mindtwo\LaravelIdentity\Oidc\SubjectResolvers\PairwiseSubjectResolver;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;
use RuntimeException;

class PairwiseSubjectResolverTest extends TestCase
{
    public function test_subject_is_deterministic_for_same_inputs(): void
    {
        $user = new TestUser(['id' => 42]);
        $client = new Client;
        $client->redirect_uris = ['https://app.example.com/callback'];

        $resolver = new PairwiseSubjectResolver;

        $this->assertSame(
            $resolver->resolve($user, $client),
            $resolver->resolve($user, $client),
        );
    }

    public function test_subject_differs_across_different_sector_identifiers(): void
    {
        $user = new TestUser(['id' => 42]);

        $client1 = new Client;
        $client1->redirect_uris = ['https://app1.example.com/callback'];

        $client2 = new Client;
        $client2->redirect_uris = ['https://app2.example.com/callback'];

        $resolver = new PairwiseSubjectResolver;

        $this->assertNotSame(
            $resolver->resolve($user, $client1),
            $resolver->resolve($user, $client2),
        );
    }

    public function test_same_sector_identifier_produces_same_subject(): void
    {
        $user = new TestUser(['id' => 42]);

        $client1 = new Client;
        $client1->redirect_uris = ['https://same.example.com/cb1'];

        $client2 = new Client;
        $client2->redirect_uris = ['https://same.example.com/cb2'];

        $resolver = new PairwiseSubjectResolver;

        $this->assertSame(
            $resolver->resolve($user, $client1),
            $resolver->resolve($user, $client2),
        );
    }

    public function test_throws_when_pairwise_salt_not_configured(): void
    {
        config(['identity.pairwise_salt' => null]);

        $user = new TestUser(['id' => 1]);
        $client = new Client;
        $client->redirect_uris = ['https://example.com/cb'];

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('pairwise_salt');

        new PairwiseSubjectResolver()->resolve($user, $client);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('identity.pairwise_salt', 'test-salt-123');
    }
}
