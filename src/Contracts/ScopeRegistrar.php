<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Contracts;

interface ScopeRegistrar
{
    /**
     * Return all claim names grantable by the given scopes.
     *
     * @param list<string> $scopes
     *
     * @return list<string>
     */
    public function claimsFor(array $scopes): array;

    /**
     * Map additional claim names to a scope.
     *
     * @param list<string> $claims
     */
    public function register(string $scope, array $claims): void;

    /**
     * All registered scope names.
     *
     * @return list<string>
     */
    public function all(): array;

    /**
     * All registered claim names across every scope.
     *
     * @return list<string>
     */
    public function allClaims(): array;
}
