<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Contracts\SessionIdResolver;
use Chiiya\LaravelIdentity\Identity;
use Chiiya\LaravelIdentity\Logout\FrontChannelOrchestrator;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Laravel\Passport\Client;

class FrontChannelLogoutController
{
    public function __construct(
        private readonly FrontChannelOrchestrator $orchestrator,
        private readonly SessionIdResolver $sidResolver,
    ) {}

    public function show(Request $request): Response
    {
        if (! $request->user()) {
            abort(401);
        }

        $user = $request->user();
        $fcClients = $this->orchestrator->relevantClients($user);

        $iframeUrls = $fcClients->map(function (Client $client) use ($user): string {
            $sid = $this->sidResolver->find($user, $client);

            return $this->orchestrator->buildIframeUrl($client, $sid);
        })->values()->all();

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
