<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Session;

use Chiiya\LaravelIdentity\Contracts\SessionIdResolver;
use DateTimeImmutable;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\OAuthenticatable;

class SidManager implements SessionIdResolver
{
    public function __construct(
        private readonly Request $request,
    ) {}

    public function forCurrentRequest(OAuthenticatable $user, Client $client, DateTimeImmutable $authTime): string
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
                'auth_time' => $authTime,
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

    public function recover(OAuthenticatable $user, Client $client): ?array
    {
        $session = OidcSession::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('client_id', (string) $client->getKey())
            ->whereNull('revoked_at')
            ->latest('last_seen_at')
            ->first();

        if ($session === null) {
            return null;
        }

        return [
            'sid' => $session->id,
            'auth_time' => ($session->auth_time ?? $session->created_at)->getTimestamp(),
        ];
    }

    public function invalidate(OAuthenticatable $user): void
    {
        OidcSession::where('user_id', $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }
}
