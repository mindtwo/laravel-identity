<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class UserInfoEndpointTest extends TestCase
{
    public function test_returns_sub_for_a_token_with_openid_scope(): void
    {
        $user = $this->user();
        Passport::actingAs($user, ['openid'], 'api');

        $response = $this->getJson('/oauth/userinfo');

        $response->assertOk();
        $response->assertJson(['sub' => (string) $user->getAuthIdentifier()]);
        $response->assertHeader('Cache-Control', 'no-store, private');
    }

    public function test_requires_the_openid_scope(): void
    {
        Passport::actingAs($this->user(), [], 'api');

        $this->getJson('/oauth/userinfo')->assertForbidden();
    }

    public function test_requires_authentication(): void
    {
        $this->getJson('/oauth/userinfo')->assertUnauthorized();
    }

    private function user(): TestUser
    {
        return TestUser::query()->create([
            'name' => 'Ada Lovelace',
            'email' => 'ada@example.com',
            'password' => bcrypt('secret'),
        ]);
    }
}
