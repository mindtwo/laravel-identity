<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Contracts\SessionIdResolver;
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
        private readonly SessionIdResolver $sidResolver,
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
            $client = $this->resolveClientFromRequest($request);

            // OIDC max_age: re-authenticate when the existing session is older than
            // the requested max_age, falling back to the client's registered
            // default_max_age (Core 1.0 §2, §3.1.2.1).
            $this->enforceMaxAge($this->effectiveMaxAge($context, $client), $authTime, $request);

            if ($client instanceof Client) {
                // Mint the session id here (the web session exists) and stash it with
                // nonce + auth_time so the auth code repository can bind them to the
                // issued auth code, ultimately reaching the id_token.
                $request->session()->put('identity.oidc_auth', [
                    'nonce' => $context->nonce,
                    'auth_time' => $authTime->getTimestamp(),
                    'sid' => $this->sidResolver->forCurrentRequest($user, $client, $authTime),
                ]);

                $this->events->dispatch(new AuthorizationRequestValidated($user, $client, $context));
            }
        }

        return parent::authorize($psrRequest, $request, $psrResponse, $viewResponse);
    }

    private function effectiveMaxAge(AuthRequestContext $context, ?Client $client): ?int
    {
        if ($context->maxAge !== null) {
            return $context->maxAge;
        }

        if ($client instanceof Client && method_exists($client, 'getDefaultMaxAge')) {
            return $client->getDefaultMaxAge();
        }

        return null;
    }

    private function enforceMaxAge(?int $maxAge, DateTimeImmutable $authTime, Request $request): void
    {
        if ($maxAge === null) {
            return;
        }

        if ($request->session()->get('promptedForLogin', false)) {
            return;
        }

        $elapsed = new DateTimeImmutable()->getTimestamp() - $authTime->getTimestamp();

        if ($elapsed <= $maxAge) {
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
