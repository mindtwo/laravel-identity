<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

use Chiiya\LaravelIdentity\Exceptions\ConsentRequired;
use DateTimeImmutable;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

class PromptHandler
{
    /**
     * Evaluate the `prompt` and `max_age` parameters.
     *
     * Returns true if processing should continue silently.
     * Throws ConsentRequired or redirects for re-authentication as appropriate.
     *
     * @throws ConsentRequired
     * @throws \Chiiya\LaravelIdentity\Exceptions\LoginRequired
     */
    public function evaluate(
        AuthRequestContext $context,
        OAuthenticatable $user,
        Client $client,
        bool $isFirstParty,
    ): void {
        // max_age=0 means the user must have just authenticated (fresh login required).
        if ($context->maxAge !== null) {
            $elapsedSinceAuth = (new DateTimeImmutable())->getTimestamp() - $context->authTime->getTimestamp();

            if ($elapsedSinceAuth > $context->maxAge) {
                throw new \Chiiya\LaravelIdentity\Exceptions\LoginRequired(
                    'Authentication time exceeds max_age.',
                );
            }
        }

        $prompt = $context->prompt;

        if ($prompt === 'none') {
            // Must not display any UI.
            // For first-party clients the consent was pre-granted.
            if (! $isFirstParty) {
                throw new ConsentRequired('User consent is required but prompt=none was requested.');
            }

            return;
        }

        if ($prompt === 'login') {
            // Force re-authentication regardless of active session.
            throw new \Chiiya\LaravelIdentity\Exceptions\LoginRequired(
                'prompt=login requires re-authentication.',
            );
        }

        if ($prompt === 'consent') {
            // Force consent display even for first-party clients.
            throw new ConsentRequired('prompt=consent requires explicit user consent.');
        }
    }
}
