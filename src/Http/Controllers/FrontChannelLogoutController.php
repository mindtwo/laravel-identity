<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Http\Controllers;

use Illuminate\Http\Request;
use Mindtwo\LaravelIdentity\Http\Responses\ViewResponse;
use Mindtwo\LaravelIdentity\Identity;
use Mindtwo\LaravelIdentity\Logout\FrontChannelOrchestrator;
use Symfony\Component\HttpFoundation\Response;

class FrontChannelLogoutController
{
    public function __construct(
        private readonly FrontChannelOrchestrator $orchestrator,
    ) {}

    public function show(Request $request): Response
    {
        if (! $request->user()) {
            abort(401);
        }

        $iframeUrls = $this->orchestrator->buildIframeUrls($request->user());

        $redirectUri = $this->safeRedirect($request->input('redirect'));

        $view = Identity::$frontChannelLogoutLayout ?? 'identity::front-channel-logout';

        return (new ViewResponse($view, [
            'iframeUrls' => $iframeUrls,
            'redirectUri' => $redirectUri,
        ]))->toResponse($request);
    }

    /**
     * Constrain the post-logout landing target to a local, relative path. An
     * attacker-supplied absolute or protocol-relative URL would otherwise turn
     * this endpoint into an open redirect.
     */
    private function safeRedirect(mixed $redirect): string
    {
        if (! is_string($redirect) || $redirect === '') {
            return '/';
        }

        if (! str_starts_with($redirect, '/')
            || str_starts_with($redirect, '//')
            || str_starts_with($redirect, '/\\')) {
            return '/';
        }

        return $redirect;
    }
}
