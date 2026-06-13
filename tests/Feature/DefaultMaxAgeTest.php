<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use DateTimeImmutable;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class DefaultMaxAgeTest extends TestCase
{
    public function test_client_default_max_age_forces_reauthentication_when_session_is_stale(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
            'default_max_age' => 1,
        ]);

        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);
        $user->setAuthTime(new DateTimeImmutable('-1 hour'));

        $this->authorize($client, $user)->assertRedirect('/login');
    }

    public function test_stale_session_with_prompt_none_returns_login_required_error(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
            'default_max_age' => 1,
        ]);

        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);
        $user->setAuthTime(new DateTimeImmutable('-1 hour'));

        Route::middleware('web')->get('/login', fn (): string => 'login')->name('login');

        // prompt=none forbids any UI: stale max_age must yield a login_required
        // error redirect to the RP, never the /login page (Core 1.0 §3.1.2.1).
        $response = $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
            'prompt' => 'none',
            'state' => 'xyz',
        ]));

        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');
        $this->assertStringStartsWith('https://app.example.com/cb', $location);
        $this->assertStringContainsString('error=login_required', $location);
        $this->assertStringContainsString('state=xyz', $location);
    }

    public function test_fresh_session_within_default_max_age_is_approved(): void
    {
        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
            'default_max_age' => 3600,
        ]);

        $user = TestUser::query()->create(['name' => 'T', 'email' => 't@e.com', 'password' => bcrypt('x')]);
        $user->setAuthTime(new DateTimeImmutable);

        $response = $this->authorize($client, $user);

        $response->assertRedirect();
        $this->assertStringContainsString('code=', (string) $response->headers->get('Location'));
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

    private function authorize(Client $client, TestUser $user)
    {
        Route::middleware('web')->get('/login', fn (): string => 'login')->name('login');

        return $this->actingAs($user)->get(route('passport.authorizations.authorize', [
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://app.example.com/cb',
            'response_type' => 'code',
            'scope' => 'openid',
        ]));
    }
}
