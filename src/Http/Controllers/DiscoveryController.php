<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Mindtwo\LaravelIdentity\Contracts\DiscoveryDocumentBuilder;

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
