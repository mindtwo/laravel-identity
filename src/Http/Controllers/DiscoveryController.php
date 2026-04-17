<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Controllers;

use Chiiya\LaravelIdentity\Contracts\DiscoveryDocumentBuilder;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;

class DiscoveryController
{
    public function __construct(
        private readonly DiscoveryDocumentBuilder $builder,
    ) {}

    public function show(): JsonResponse
    {
        $ttl = (int) config('identity.discovery_cache_ttl', 3600);

        $document = $ttl > 0
            ? Cache::remember('identity:discovery', $ttl, fn () => $this->builder->build())
            : $this->builder->build();

        return response()->json($document)
            ->header('Cache-Control', "public, max-age={$ttl}");
    }
}
