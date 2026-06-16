<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Unit\Session;

use Illuminate\Database\Eloquent\Model;
use Mindtwo\LaravelIdentity\Session\OidcSession;
use Mindtwo\LaravelIdentity\Tests\TestCase;

/**
 * SidManager mass-assigns `revoked_at` (firstOrCreate with revoked_at => null, and
 * update(['revoked_at' => now()])). Consumer apps that enable Model::shouldBeStrict()
 * turn on preventSilentlyDiscardingAttributes, which would throw a MassAssignmentException
 * and 500 the /oauth/authorize flow unless `revoked_at` is fillable.
 */
class OidcSessionStrictModeTest extends TestCase
{
    public function test_oidc_session_can_be_created_and_revoked_under_strict_mode(): void
    {
        $session = OidcSession::create([
            'user_id' => '1',
            'client_id' => 'client-1',
            'laravel_session_id' => 'session-1',
            'auth_time' => now(),
            'created_at' => now(),
            'last_seen_at' => now(),
            'revoked_at' => null,
        ]);

        $this->assertNull($session->revoked_at);

        $session->update(['revoked_at' => now()]);

        $this->assertNotNull($session->fresh()->revoked_at);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Model::preventSilentlyDiscardingAttributes();
    }

    protected function tearDown(): void
    {
        Model::preventSilentlyDiscardingAttributes(false);

        parent::tearDown();
    }
}
