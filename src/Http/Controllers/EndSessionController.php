<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Contracts\LogoutEventListener;
use Chiiya\LaravelIdentity\Contracts\SessionIdResolver;
use Chiiya\LaravelIdentity\Events\UserLoggedOut;
use Chiiya\LaravelIdentity\Exceptions\InvalidRpLogoutRequest;
use Chiiya\LaravelIdentity\Http\Requests\EndSessionRequest;
use Chiiya\LaravelIdentity\Logout\FrontChannelOrchestrator;
use Chiiya\LaravelIdentity\Logout\RpInitiatedLogoutValidator;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Laravel\Passport\Contracts\OAuthenticatable;
use RuntimeException;

class EndSessionController
{
    public function __construct(
        private readonly RpInitiatedLogoutValidator $validator,
        private readonly FrontChannelOrchestrator $orchestrator,
        private readonly SessionIdResolver $sidResolver,
        private readonly Container $container,
        private readonly Dispatcher $events,
    ) {}

    /**
     * Show the RP-initiated logout confirmation screen (or proceed silently for first-party).
     */
    public function show(EndSessionRequest $request): Response|RedirectResponse
    {
        if (! $request->user()) {
            return redirect('/');
        }

        if ($request->isMethod('post')) {
            return $this->performLogout($request);
        }

        if (! $request->filled('id_token_hint') && ! $request->filled('client_id')) {
            return $this->localLogout($request);
        }

        try {
            $logoutRequest = $this->validator->validate(
                $request->input('id_token_hint'),
                $request->input('post_logout_redirect_uri'),
                $request->input('state'),
                $request->input('client_id'),
            );
        } catch (InvalidRpLogoutRequest) {
            abort(400, 'Invalid logout request.');
        }

        // Validate subject matches current user when a token hint is provided.
        if (! empty($logoutRequest->subject)) {
            $userId = (string) $request->user()->getAuthIdentifier();

            if ($logoutRequest->subject !== $userId) {
                abort(403, 'The id_token_hint subject does not match the current user.');
            }
        }

        // First-party clients may skip confirmation.
        $isFirstParty = method_exists($logoutRequest->client, 'isFirstParty')
            && $logoutRequest->client->isFirstParty();

        if ($isFirstParty) {
            return $this->executeLogout($request, $logoutRequest->client, $logoutRequest->postLogoutRedirectUri, $logoutRequest->state);
        }

        $view = \Chiiya\LaravelIdentity\Identity::$endSessionView;

        if ($view === null) {
            throw new RuntimeException(
                'Register a logout confirmation view via Identity::endSessionView() in your AppServiceProvider.',
            );
        }

        return response()->view(is_callable($view) ? $view() : $view, [
            'client' => $logoutRequest->client,
            'request' => $logoutRequest,
            'state' => $logoutRequest->state,
        ]);
    }

    public function performLogout(EndSessionRequest $request): Response|RedirectResponse
    {
        if (! $request->user()) {
            return redirect('/');
        }

        if (! $request->filled('id_token_hint') && ! $request->filled('client_id')) {
            return $this->localLogout($request);
        }

        try {
            $logoutRequest = $this->validator->validate(
                $request->input('id_token_hint'),
                $request->input('post_logout_redirect_uri'),
                $request->input('state'),
                $request->input('client_id'),
            );
        } catch (InvalidRpLogoutRequest) {
            abort(400, 'Invalid logout request.');
        }

        return $this->executeLogout(
            $request,
            $logoutRequest->client,
            $logoutRequest->postLogoutRedirectUri,
            $logoutRequest->state,
        );
    }

    private function executeLogout(
        Request $request,
        \Laravel\Passport\Client $client,
        ?string $redirectUri,
        ?string $state,
    ): Response|RedirectResponse {
        /** @var OAuthenticatable $user */
        $user = $request->user();

        $event = new UserLoggedOut($user, $client);

        // Run synchronous listeners first (e.g. token revocation that must complete before redirect).
        foreach ($this->container->tagged('identity.logout_listeners') as $listener) {
            /** @var LogoutEventListener $listener */
            $listener->handle($event);
        }

        $this->events->dispatch($event);
        $this->sidResolver->invalidate($user);

        $fcClients = $this->orchestrator->relevantClients($user);

        // Perform Laravel logout.
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        if ($fcClients->isNotEmpty()) {
            $iframeUrls = $fcClients->map(function (\Laravel\Passport\Client $fc) use ($user): string {
                $sid = $this->sidResolver->find($user, $fc);

                return $this->orchestrator->buildIframeUrl($fc, $sid);
            })->values()->all();

            $finalRedirect = $this->buildFinalRedirectUrl($redirectUri, $state);

            $layout = \Chiiya\LaravelIdentity\Identity::$frontChannelLogoutLayout;

            $componentData = [
                'iframeUrls' => $iframeUrls,
                'redirectUri' => $finalRedirect,
            ];

            if ($layout !== null) {
                $layoutView = is_callable($layout) ? $layout() : $layout;

                return response()->view($layoutView, $componentData);
            }

            return response()->view('identity::front-channel-logout', $componentData);
        }

        return redirect($this->buildFinalRedirectUrl($redirectUri, $state) ?? '/');
    }

    private function localLogout(Request $request): RedirectResponse
    {
        /** @var OAuthenticatable $user */
        $user = $request->user();

        $event = new UserLoggedOut($user, null);

        foreach ($this->container->tagged('identity.logout_listeners') as $listener) {
            /** @var LogoutEventListener $listener */
            $listener->handle($event);
        }

        $this->events->dispatch($event);
        $this->sidResolver->invalidate($user);

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }

    private function buildFinalRedirectUrl(?string $uri, ?string $state): ?string
    {
        if ($uri === null) {
            return null;
        }

        if ($state !== null) {
            $separator = str_contains($uri, '?') ? '&' : '?';
            $uri .= $separator.'state='.urlencode($state);
        }

        return $uri;
    }
}
