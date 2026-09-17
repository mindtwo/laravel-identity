<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Http\Controllers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\RedirectResponse;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;
use Mindtwo\LaravelIdentity\Contracts\LogoutEventListener;
use Mindtwo\LaravelIdentity\Contracts\SessionIdResolver;
use Mindtwo\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Mindtwo\LaravelIdentity\Events\UserLoggedOut;
use Mindtwo\LaravelIdentity\Exceptions\InvalidRpLogoutRequest;
use Mindtwo\LaravelIdentity\Http\Requests\EndSessionRequest;
use Mindtwo\LaravelIdentity\Http\Responses\ViewResponse;
use Mindtwo\LaravelIdentity\Identity;
use Mindtwo\LaravelIdentity\Logout\FrontChannelOrchestrator;
use Mindtwo\LaravelIdentity\Logout\LogoutRequest;
use Mindtwo\LaravelIdentity\Logout\RpInitiatedLogoutValidator;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * RP-Initiated Logout endpoint.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */
class EndSessionController
{
    public function __construct(
        private readonly RpInitiatedLogoutValidator $validator,
        private readonly FrontChannelOrchestrator $orchestrator,
        private readonly SessionIdResolver $sidResolver,
        private readonly SubjectIdentifierResolver $subjectResolver,
        private readonly Container $container,
        private readonly Dispatcher $events,
    ) {}

    /**
     * GET: show the confirmation screen for a non-first-party client, otherwise
     * proceed to log out.
     */
    public function show(EndSessionRequest $request): Response
    {
        $user = $request->user();

        if (! $user instanceof OAuthenticatable) {
            return $this->redirectWithoutSession($request);
        }

        if (! $this->hasRpContext($request)) {
            return $this->endSession($request, $user, client: null, redirectUri: null, state: null);
        }

        $logout = $this->validatedRequest($request);
        $this->assertSubjectMatchesUser($user, $logout);

        // RP-Initiated Logout §6: confirm with the End-User before logging out,
        // unless the client is trusted (first-party).
        if (! Identity::clientIsFirstParty($logout->client)) {
            return $this->confirmationScreen($request, $logout);
        }

        return $this->endSession($request, $user, $logout->client, $logout->postLogoutRedirectUri, $logout->state);
    }

    /**
     * POST: the logout is already confirmed, so always proceed.
     */
    public function logout(EndSessionRequest $request): Response
    {
        $user = $request->user();

        if (! $user instanceof OAuthenticatable) {
            return $this->redirectWithoutSession($request);
        }

        if (! $this->hasRpContext($request)) {
            return $this->endSession($request, $user, client: null, redirectUri: null, state: null);
        }

        $logout = $this->validatedRequest($request);
        $this->assertSubjectMatchesUser($user, $logout);

        return $this->endSession($request, $user, $logout->client, $logout->postLogoutRedirectUri, $logout->state);
    }

    private function hasRpContext(EndSessionRequest $request): bool
    {
        return $request->filled('id_token_hint') || $request->filled('client_id');
    }

    /**
     * Validate the RP logout request, aborting with 400 when it is malformed or the
     * post_logout_redirect_uri is not registered for the client.
     */
    private function validatedRequest(EndSessionRequest $request): LogoutRequest
    {
        try {
            return $this->validator->validate(
                $request->input('id_token_hint'),
                $request->input('post_logout_redirect_uri'),
                $request->input('state'),
                $request->input('client_id'),
            );
        } catch (InvalidRpLogoutRequest) {
            abort(400, 'Invalid logout request.');
        }
    }

    /**
     * The id_token_hint subject is client-specific (e.g. pairwise), so compare it
     * through the same resolver used at issuance rather than the raw identifier. A
     * client_id-only request carries no subject and is skipped.
     */
    private function assertSubjectMatchesUser(OAuthenticatable $user, LogoutRequest $logout): void
    {
        if ($logout->subject === '') {
            return;
        }

        $expected = $this->subjectResolver->resolve($user, $logout->client);

        if (! hash_equals($expected, $logout->subject)) {
            abort(403, 'The id_token_hint subject does not match the current user.');
        }
    }

    private function confirmationScreen(EndSessionRequest $request, LogoutRequest $logout): Response
    {
        $view = Identity::$endSessionView;

        if ($view === null) {
            throw new RuntimeException(
                'Register a logout confirmation view via Identity::endSessionView() in your AppServiceProvider.',
            );
        }

        return (new ViewResponse($view, [
            'client' => $logout->client,
            'request' => $logout,
            'state' => $logout->state,
        ]))->toResponse($request);
    }

    /**
     * Terminate the OP session: notify listeners, propagate front-channel logout to
     * the user's other RPs, tear down the session, then redirect — or render the
     * front-channel iframe page first when there are RPs to notify.
     */
    private function endSession(
        EndSessionRequest $request,
        OAuthenticatable $user,
        ?Client $client,
        ?string $redirectUri,
        ?string $state,
    ): Response {
        $event = new UserLoggedOut($user, $client);

        // Synchronous listeners run first (e.g. token revocation that must complete
        // before the redirect); fire-and-forget work can listen to the dispatched event.
        foreach ($this->container->tagged('identity.logout_listeners') as $listener) {
            // @var LogoutEventListener $listener
            $listener->handle($event);
        }

        $this->events->dispatch($event);

        // Capture iframe URLs BEFORE revoking sessions, otherwise the sids are gone.
        // Front-channel propagation applies to RP-initiated logout; a plain local
        // logout (no client) does not notify other RPs.
        $iframeUrls = $client instanceof Client ? $this->orchestrator->buildIframeUrls($user) : [];

        $this->sidResolver->invalidate($user);
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $target = $this->finalRedirectUrl($redirectUri, $state) ?? '/';

        return $iframeUrls === []
            ? redirect($target)
            : $this->frontChannelPage($request, $iframeUrls, $target);
    }

    /**
     * Render the front-channel logout page that loads each RP's logout iframe and
     * then continues to $redirectUri. Apps may supply their own wrapper view via
     * Identity::frontChannelLogoutLayout().
     *
     * @param list<string> $iframeUrls
     */
    private function frontChannelPage(EndSessionRequest $request, array $iframeUrls, string $redirectUri): Response
    {
        $view = Identity::$frontChannelLogoutLayout ?? 'identity::front-channel-logout';

        return (new ViewResponse($view, [
            'iframeUrls' => $iframeUrls,
            'redirectUri' => $redirectUri,
        ]))->toResponse($request);
    }

    /**
     * No active session: honor a validated post_logout_redirect_uri so the RP can
     * complete its flow, otherwise land on home.
     */
    private function redirectWithoutSession(EndSessionRequest $request): RedirectResponse
    {
        if (! $this->hasRpContext($request)) {
            return redirect('/');
        }

        $logout = $this->validatedRequest($request);

        return redirect($this->finalRedirectUrl($logout->postLogoutRedirectUri, $logout->state) ?? '/');
    }

    private function finalRedirectUrl(?string $uri, ?string $state): ?string
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
