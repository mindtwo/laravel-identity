<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Contracts;

use Mindtwo\LaravelIdentity\Events\UserLoggedOut;

/**
 * Synchronous pre-redirect logout hook.
 *
 * Useful when token revocation or upstream IdP logout MUST complete before
 * the browser is redirected. For async/fire-and-forget cleanup, listen to
 * the UserLoggedOut event via Laravel's event system instead.
 *
 * Bind implementations tagged 'identity.logout_listeners' in a service provider.
 */
interface LogoutEventListener
{
    public function handle(UserLoggedOut $event): void;
}
