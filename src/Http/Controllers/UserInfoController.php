<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Chiiya\LaravelIdentity\Oidc\ClaimAggregator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\Client;

class UserInfoController
{
    public function __construct(
        private readonly ClaimAggregator $claimAggregator,
        private readonly SubjectIdentifierResolver $subjectResolver,
    ) {}

    public function show(Request $request): JsonResponse
    {
        /** @var \Laravel\Passport\Contracts\OAuthenticatable $user */
        $user = $request->user();
        $token = $request->user()->token();
        $scopes = $token?->scopes ?? [];
        $clientId = $token?->client_id;

        $client = $clientId !== null ? Client::find($clientId) : null;
        $subject = $client !== null
            ? $this->subjectResolver->resolve($user, $client)
            : (string) $user->getAuthIdentifier();

        $claims = $this->claimAggregator->aggregate($user, $scopes);
        $claims['sub'] = $subject;

        return response()->json($claims)
            ->header('Cache-Control', 'no-store');
    }
}
