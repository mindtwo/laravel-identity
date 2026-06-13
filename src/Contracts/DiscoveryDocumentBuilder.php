<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Contracts;

interface DiscoveryDocumentBuilder
{
    /**
     * Build the OpenID Connect Discovery 1.0 document.
     *
     * @return array<string, mixed>
     */
    public function build(): array;
}
