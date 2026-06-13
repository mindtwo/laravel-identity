<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Laravel\Passport\Client;
use Mindtwo\LaravelIdentity\Http\Requests\IntrospectRequest;
use Mindtwo\LaravelIdentity\Introspection\TokenIntrospector;

class IntrospectionController
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
    ) {}

    public function introspect(IntrospectRequest $request): JsonResponse
    {
        /** @var Client $client */
        $client = $request->attributes->get('identity_client');

        // token_type_hint is validated and accepted per RFC 7662 §2.1 but carries
        // no optimization value here (only access tokens are introspectable).
        $payload = $this->introspector->introspect($request->validated('token'), $client);

        return response()->json($payload)
            ->header('Cache-Control', 'no-store');
    }
}
