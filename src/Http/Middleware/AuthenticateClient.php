<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Client;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticates the calling client via client_secret_basic or client_secret_post.
 * Attaches the resolved client as 'identity_client' on the request.
 */
class AuthenticateClient
{
    public function handle(Request $request, Closure $next): Response
    {
        $client = $this->resolveClient($request);

        if (! $client instanceof Client) {
            return response()->json(
                [
                    'error' => 'invalid_client',
                    'error_description' => 'Client authentication failed.',
                ],
                401,
                ['WWW-Authenticate' => 'Basic realm="identity"'],
            );
        }

        $request->attributes->set('identity_client', $client);

        return $next($request);
    }

    private function resolveClient(Request $request): ?Client
    {
        // client_secret_basic: Authorization: Basic base64(client_id:client_secret)
        if ($request->hasHeader('Authorization')) {
            $header = $request->header('Authorization', '');

            if (str_starts_with($header, 'Basic ')) {
                $decoded = base64_decode(mb_substr($header, 6), true);
                [$clientId, $clientSecret] = explode(':', $decoded, 2) + [1 => ''];

                return $this->validateClient($clientId, $clientSecret);
            }
        }

        // client_secret_post
        if ($request->filled('client_id') && $request->filled('client_secret')) {
            return $this->validateClient($request->input('client_id'), $request->input('client_secret'));
        }

        return null;
    }

    private function validateClient(string $clientId, string $secret): ?Client
    {
        $client = Client::find($clientId);

        if ($client === null || $client->revoked) {
            return null;
        }

        if (! Hash::check($secret, $client->secret)) {
            return null;
        }

        return $client;
    }
}
