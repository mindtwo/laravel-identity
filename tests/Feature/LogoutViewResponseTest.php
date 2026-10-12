<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\View;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Identity;
use Mindtwo\LaravelIdentity\Session\OidcSession;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestClient;
use Mindtwo\LaravelIdentity\Tests\Fixtures\TestUser;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class LogoutViewResponseTest extends TestCase
{
    public function test_confirmation_screen_renders_a_view_name(): void
    {
        Identity::endSessionView('test::logout-confirm');

        $this->confirmationResponse()
            ->assertOk()
            ->assertSee('Confirm logout from Acme with state xyz');
    }

    public function test_confirmation_screen_renders_a_view_name_returned_by_a_closure(): void
    {
        Identity::endSessionView(fn (): string => 'test::logout-confirm');

        $this->confirmationResponse()
            ->assertOk()
            ->assertSee('Confirm logout from Acme with state xyz');
    }

    public function test_confirmation_screen_renders_a_responsable_returned_by_a_closure(): void
    {
        Identity::endSessionView(fn (array $data): Responsable => new class($data) implements Responsable {
            /**
             * @param array<string, mixed> $data
             */
            public function __construct(
                private readonly array $data,
            ) {}

            public function toResponse($request): JsonResponse
            {
                return new JsonResponse([
                    'component' => 'Auth/LogoutConfirm',
                    'props' => [
                        'client' => $this->data['client']->name,
                        'state' => $this->data['state'],
                    ],
                ]);
            }
        });

        $this->confirmationResponse()
            ->assertOk()
            ->assertExactJson([
                'component' => 'Auth/LogoutConfirm',
                'props' => [
                    'client' => 'Acme',
                    'state' => 'xyz',
                ],
            ]);
    }

    public function test_confirmation_screen_renders_a_response_returned_by_a_closure(): void
    {
        Identity::endSessionView(fn (array $data) => response("Bye {$data['client']->name}", 200));

        $this->confirmationResponse()
            ->assertOk()
            ->assertSee('Bye Acme');
    }

    public function test_front_channel_layout_renders_a_responsable_returned_by_a_closure(): void
    {
        Identity::frontChannelLogoutLayout(fn (array $data): Responsable => new class($data) implements Responsable {
            /**
             * @param array<string, mixed> $data
             */
            public function __construct(
                private readonly array $data,
            ) {}

            public function toResponse($request): JsonResponse
            {
                return new JsonResponse($this->data);
            }
        });

        $client = Client::factory()->create([
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => true,
            'frontchannel_logout_uri' => 'https://app.example.com/frontchannel-logout',
        ]);

        $user = $this->createUser();

        OidcSession::query()->create([
            'user_id' => $user->getAuthIdentifier(),
            'client_id' => (string) $client->getKey(),
            'laravel_session_id' => 'sess-1',
            'created_at' => now(),
            'last_seen_at' => now(),
        ]);

        $this->actingAs($user)
            ->post(route('identity.end_session'), ['client_id' => (string) $client->getKey()])
            ->assertOk()
            ->assertExactJson([
                'iframeUrls' => ['https://app.example.com/frontchannel-logout'],
                'redirectUri' => '/',
            ]);
    }

    public function test_front_channel_endpoint_renders_a_responsable_returned_by_a_closure(): void
    {
        Identity::frontChannelLogoutLayout(fn (array $data) => new JsonResponse($data));

        $this->actingAs($this->createUser())
            ->get(route('identity.frontchannel_logout', ['redirect' => '/dashboard']))
            ->assertOk()
            ->assertExactJson([
                'iframeUrls' => [],
                'redirectUri' => '/dashboard',
            ]);
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        Passport::useClientModel(TestClient::class);
        View::addNamespace('test', __DIR__.'/../Fixtures/views');
    }

    private function confirmationResponse(): TestResponse
    {
        $client = Client::factory()->create([
            'name' => 'Acme',
            'redirect_uris' => ['https://app.example.com/cb'],
            'first_party' => false,
        ]);

        return $this->actingAs($this->createUser())->get(route('identity.end_session', [
            'client_id' => (string) $client->getKey(),
            'state' => 'xyz',
        ]));
    }

    private function createUser(): TestUser
    {
        return TestUser::query()->create([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => bcrypt('secret'),
        ]);
    }
}
