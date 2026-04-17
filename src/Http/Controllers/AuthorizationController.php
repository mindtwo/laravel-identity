<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Events\AuthorizationRequestValidated;
use Chiiya\LaravelIdentity\Exceptions\ConsentRequired;
use Chiiya\LaravelIdentity\Exceptions\LoginRequired;
use Chiiya\LaravelIdentity\Oidc\AuthRequestContext;
use Chiiya\LaravelIdentity\Oidc\NonceStore;
use Chiiya\LaravelIdentity\Oidc\PromptHandler;
use DateTimeImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Laravel\Passport\Http\Controllers\AuthorizationController as PassportAuthorizationController;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationController extends PassportAuthorizationController
{
    public function __construct(
        private readonly NonceStore $nonceStore,
        private readonly PromptHandler $promptHandler,
        private readonly Dispatcher $events,
    ) {}

    public function authorize(
        ServerRequestInterface $psrRequest,
        Request $request,
        \Laravel\Passport\ClientRepository $clients,
        \Laravel\Passport\TokenRepository $tokens,
    ): mixed {
        $user = $request->user();
        $authTime = $this->resolveAuthTime($user);
        $context = AuthRequestContext::fromRequest($request, $authTime);

        if ($user !== null) {
            $client = $this->resolveClientFromRequest($request, $clients);

            if ($client !== null) {
                $isFirstParty = method_exists($client, 'isFirstParty') && $client->isFirstParty();

                // Evaluate prompt and max_age constraints.
                try {
                    $this->promptHandler->evaluate($context, $user, $client, $isFirstParty);
                } catch (ConsentRequired $e) {
                    return $this->buildErrorRedirect($request, 'consent_required', $e->getMessage());
                } catch (LoginRequired $e) {
                    return $this->buildErrorRedirect($request, 'login_required', $e->getMessage());
                }

                // Store nonce for later pickup by IdTokenResponseType.
                if ($context->nonce !== null) {
                    $this->nonceStore->storePreCode(
                        (string) $user->getAuthIdentifier(),
                        (string) $client->getKey(),
                        (string) $request->input('state', ''),
                        $context->nonce,
                        $authTime,
                    );
                }

                $this->events->dispatch(new AuthorizationRequestValidated($user, $client, $context));
            }
        }

        return parent::authorize($psrRequest, $request, $clients, $tokens);
    }

    private function resolveAuthTime(\Laravel\Passport\Contracts\OAuthenticatable|null $user): DateTimeImmutable
    {
        if ($user !== null && method_exists($user, 'getAuthTime')) {
            $authTime = $user->getAuthTime();

            if ($authTime instanceof \DateTimeInterface) {
                return DateTimeImmutable::createFromInterface($authTime);
            }

            if (is_int($authTime)) {
                return (new DateTimeImmutable())->setTimestamp($authTime);
            }
        }

        return new DateTimeImmutable();
    }

    private function resolveClientFromRequest(
        Request $request,
        \Laravel\Passport\ClientRepository $clients,
    ): ?\Laravel\Passport\Client {
        $clientId = $request->input('client_id');

        if (empty($clientId)) {
            return null;
        }

        try {
            return $clients->findActive($clientId);
        } catch (\Throwable) {
            return null;
        }
    }

    private function buildErrorRedirect(Request $request, string $error, string $description): \Illuminate\Http\RedirectResponse
    {
        $redirectUri = $request->input('redirect_uri', '/');
        $state = $request->input('state');
        $separator = str_contains($redirectUri, '?') ? '&' : '?';
        $query = http_build_query(array_filter([
            'error' => $error,
            'error_description' => $description,
            'state' => $state,
        ]));

        return redirect($redirectUri.$separator.$query);
    }
}
