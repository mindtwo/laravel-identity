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

        $redirectUri = $request->input('redirect', '/');

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
}
