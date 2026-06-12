<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Identity;
use Chiiya\LaravelIdentity\Logout\FrontChannelOrchestrator;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

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

        $layout = Identity::$frontChannelLogoutLayout;

        $data = [
            'iframeUrls' => $iframeUrls,
            'redirectUri' => $redirectUri,
        ];

        if ($layout !== null) {
            $layoutView = is_callable($layout) ? $layout() : $layout;

            return response()->view($layoutView, $data);
        }

        return response()->view('identity::front-channel-logout', $data);
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
