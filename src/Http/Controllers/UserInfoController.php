<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Passport;
use Mindtwo\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Mindtwo\LaravelIdentity\Oidc\ClaimAggregator;

class UserInfoController
{
    public function __construct(
        private readonly ClaimAggregator $claimAggregator,
        private readonly SubjectIdentifierResolver $subjectResolver,
    ) {}

    public function show(Request $request): JsonResponse
    {
        /** @var OAuthenticatable $user */
        $user = $request->user();
        $token = $request->user()->token();
        $scopes = $token?->scopes ?? [];
        $clientId = $token?->client_id;

        $client = $clientId !== null ? Passport::clientModel()::query()->find($clientId) : null;
        $subject = $client !== null
            ? $this->subjectResolver->resolve($user, $client)
            : (string) $user->getAuthIdentifier();

        $claims = $this->claimAggregator->aggregate($user, $scopes);
        $claims['sub'] = $subject;

        return response()->json($claims)
            ->header('Cache-Control', 'no-store');
    }
}
