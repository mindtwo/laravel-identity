<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Logout;

use Chiiya\LaravelIdentity\Session\OidcSession;
use Illuminate\Database\Eloquent\Collection;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

class FrontChannelOrchestrator
{
    /**
     * Return clients that have an active front-channel logout URI for the given user.
     *
     * @return Collection<int, Client>
     */
    public function relevantClients(OAuthenticatable $user): Collection
    {
        $clientIds = OidcSession::where('user_id', $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->pluck('client_id')
            ->unique()
            ->values();

        if ($clientIds->isEmpty()) {
            return new Collection();
        }

        /** @var Collection<int, Client> */
        return Client::whereIn('id', $clientIds)
            ->whereNotNull('frontchannel_logout_uri')
            ->get();
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

        return $uri.$separator.http_build_query(['iss' => $issuer, 'sid' => $sid]);
    }
}
