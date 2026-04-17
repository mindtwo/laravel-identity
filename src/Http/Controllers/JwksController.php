<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Jwks\JwksBuilder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class JwksController
{
    public function __construct(
        private readonly JwksBuilder $jwksBuilder,
    ) {}

    public function show(Request $request): JsonResponse
    {
        $etag = $this->jwksBuilder->etag();

        if ($request->header('If-None-Match') === "\"{$etag}\"") {
            return response()->json(null, 304);
        }

        return response()->json($this->jwksBuilder->build())
            ->header('Cache-Control', 'public, max-age=3600')
            ->header('ETag', "\"{$etag}\"");
    }
}
