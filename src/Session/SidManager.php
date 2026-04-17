<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Session;

use Chiiya\LaravelIdentity\Contracts\SessionIdResolver;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

class SidManager implements SessionIdResolver
{
    public function __construct(
        private readonly Request $request,
    ) {}

    public function forCurrentRequest(OAuthenticatable $user, Client $client): string
    {
        $sessionId = $this->request->hasSession() ? $this->request->session()->getId() : '';
        $userId = $user->getAuthIdentifier();
        $clientId = (string) $client->getKey();

        $session = OidcSession::firstOrCreate(
            [
                'user_id' => $userId,
                'client_id' => $clientId,
                'laravel_session_id' => $sessionId,
                'revoked_at' => null,
            ],
            [
                'created_at' => now(),
                'last_seen_at' => now(),
            ],
        );

        if ($session->wasRecentlyCreated === false) {
            $session->last_seen_at = now();
            $session->saveQuietly();
        }

        return $session->id;
    }

    public function find(OAuthenticatable $user, Client $client): ?string
    {
        $sessionId = $this->request->hasSession() ? $this->request->session()->getId() : '';

        $session = OidcSession::where('user_id', $user->getAuthIdentifier())
            ->where('client_id', (string) $client->getKey())
            ->where('laravel_session_id', $sessionId)
            ->whereNull('revoked_at')
            ->first();

        return $session?->id;
    }

    public function invalidate(OAuthenticatable $user): void
    {
        OidcSession::where('user_id', $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }
}
