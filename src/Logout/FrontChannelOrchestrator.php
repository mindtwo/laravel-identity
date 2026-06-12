<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Logout;

use Chiiya\LaravelIdentity\Session\OidcSession;
use Illuminate\Database\Eloquent\Collection;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Passport;

class FrontChannelOrchestrator
{
    /**
     * Build a front-channel logout iframe URL for every active OIDC session the
     * user holds with a client that registered a front-channel logout URI.
     *
     * Each iframe carries the session's own identifier as the `sid`, which is the
     * same value embedded in that session's id_token — guaranteeing correlation.
     *
     * @return list<string>
     */
    public function buildIframeUrls(OAuthenticatable $user): array
    {
        $sessions = OidcSession::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->get();

        if ($sessions->isEmpty()) {
            return [];
        }

        /** @var Collection<string, Client> $clients */
        $clients = Passport::clientModel()::query()
            ->whereIn('id', $sessions->pluck('client_id')->unique()->values())
            ->whereNotNull('frontchannel_logout_uri')
            ->get()
            ->keyBy(fn (Client $client): string => (string) $client->getKey());

        $urls = [];

        foreach ($sessions as $session) {
            $client = $clients->get((string) $session->client_id);

            if ($client instanceof Client) {
                $urls[] = $this->buildIframeUrl($client, $session->id);
            }
        }

        return array_values(array_unique($urls));
    }

    /**
     * Build the iframe URL for a client, appending iss/sid when required.
     */
    public function buildIframeUrl(Client $client, ?string $sid): string
    {
        $uri = method_exists($client, 'getFrontchannelLogoutUri')
            ? (string) $client->getFrontchannelLogoutUri()
            : (string) $client->frontchannel_logout_uri;

        $requiresSession = method_exists($client, 'requiresLogoutSession') && $client->requiresLogoutSession();

        if (! $requiresSession || $sid === null) {
            return $uri;
        }

        $issuer = config('identity.issuer') ?: config('app.url');
        $separator = str_contains($uri, '?') ? '&' : '?';

        return $uri.$separator.http_build_query([
            'iss' => $issuer,
            'sid' => $sid,
        ]);
    }
}
