<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Http\Requests\IntrospectRequest;
use Chiiya\LaravelIdentity\Introspection\TokenIntrospector;
use Illuminate\Http\JsonResponse;
use Laravel\Passport\Client;

class IntrospectionController
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
    ) {}

    public function introspect(IntrospectRequest $request): JsonResponse
    {
        /** @var Client $client */
        $client = $request->attributes->get('identity_client');

        $payload = $this->introspector->introspect(
            $request->validated('token'),
            $request->validated('token_type_hint'),
            $client,
        );

        return response()->json($payload)
            ->header('Cache-Control', 'no-store');
    }
}
