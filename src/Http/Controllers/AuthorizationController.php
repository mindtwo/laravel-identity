<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Events\AuthorizationRequestValidated;
use Chiiya\LaravelIdentity\Oidc\AuthRequestContext;
use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Http\Controllers\AuthorizationController as PassportAuthorizationController;
use League\OAuth2\Server\AuthorizationServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class AuthorizationController extends PassportAuthorizationController
{
    public function __construct(
        AuthorizationServer $server,
        StatefulGuard $guard,
        ClientRepository $clients,
        private readonly Dispatcher $events,
    ) {
        parent::__construct($server, $guard, $clients);
    }

    /**
     * Layer OIDC concerns (max_age, nonce, auth_time) on top of Passport's
     * spec-compliant prompt/consent/login handling, then delegate.
     */
    public function authorize(
        ServerRequestInterface $psrRequest,
        Request $request,
        ResponseInterface $psrResponse,
        AuthorizationViewResponse $viewResponse,
    ): AuthorizationViewResponse|Response {
        $user = $this->guard->user();

        if ($user instanceof OAuthenticatable) {
            $authTime = $this->resolveAuthTime($user);
            $context = AuthRequestContext::fromRequest($request, $authTime);

            // OIDC max_age: re-authenticate when the existing session is older than
            // the requested maximum authentication age (Core 1.0 §3.1.2.1).
            $this->enforceMaxAge($context, $request);

            $client = $this->resolveClientFromRequest($request);

            if ($client instanceof Client) {
                // Stash nonce + auth_time so the auth code repository can bind them
                // to the issued auth code, ultimately reaching the id_token.
                $request->session()->put('identity.oidc_auth', [
                    'nonce' => $context->nonce,
                    'auth_time' => $authTime->getTimestamp(),
                ]);

                $this->events->dispatch(new AuthorizationRequestValidated($user, $client, $context));
            }
        }

        return parent::authorize($psrRequest, $request, $psrResponse, $viewResponse);
    }

    private function enforceMaxAge(AuthRequestContext $context, Request $request): void
    {
        if ($context->maxAge === null) {
            return;
        }

        if ($request->session()->get('promptedForLogin', false)) {
            return;
        }

        $elapsed = new DateTimeImmutable()->getTimestamp() - $context->authTime->getTimestamp();

        if ($elapsed <= $context->maxAge) {
            return;
        }

        // Force a fresh login, mirroring Passport's prompt=login handling.
        $this->guard->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $this->promptForLogin($request);
    }

    private function resolveAuthTime(OAuthenticatable $user): DateTimeImmutable
    {
        if (method_exists($user, 'getAuthTime')) {
            $authTime = $user->getAuthTime();

            if ($authTime instanceof DateTimeInterface) {
                return DateTimeImmutable::createFromInterface($authTime);
            }

            if (is_int($authTime)) {
                return new DateTimeImmutable()->setTimestamp($authTime);
            }
        }

        return new DateTimeImmutable;
    }

    private function resolveClientFromRequest(Request $request): ?Client
    {
        $clientId = $request->input('client_id');

        if (empty($clientId)) {
            return null;
        }

        try {
            return $this->clients->findActive($clientId);
        } catch (Throwable) {
            return null;
        }
    }
}
