<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity;

use Chiiya\LaravelIdentity\Bridge\AuthCodeRepository;
use Chiiya\LaravelIdentity\Contracts\DiscoveryDocumentBuilder;
use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Contracts\ScopeRegistrar;
use Chiiya\LaravelIdentity\Contracts\SessionIdResolver;
use Chiiya\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Chiiya\LaravelIdentity\Discovery\DefaultDiscoveryBuilder;
use Chiiya\LaravelIdentity\Http\Controllers\AuthorizationController;
use Chiiya\LaravelIdentity\Introspection\TokenIntrospector;
use Chiiya\LaravelIdentity\Jwks\JwksBuilder;
use Chiiya\LaravelIdentity\Jwt\JwtIssuer;
use Chiiya\LaravelIdentity\Jwt\JwtValidator;
use Chiiya\LaravelIdentity\Jwt\KeyResolvers\ConfigKeyResolver;
use Chiiya\LaravelIdentity\Jwt\KeyResolvers\PassportKeyResolver;
use Chiiya\LaravelIdentity\Logout\FrontChannelOrchestrator;
use Chiiya\LaravelIdentity\Logout\RpInitiatedLogoutValidator;
use Chiiya\LaravelIdentity\Oidc\ClaimAggregator;
use Chiiya\LaravelIdentity\Oidc\IdTokenResponseType;
use Chiiya\LaravelIdentity\Oidc\NonceStore;
use Chiiya\LaravelIdentity\Oidc\Scopes\StandardClaimProvider;
use Chiiya\LaravelIdentity\Oidc\Scopes\StandardScopeRegistrar;
use Chiiya\LaravelIdentity\Oidc\SubjectResolvers\ClientAwareSubjectResolver;
use Chiiya\LaravelIdentity\Oidc\UserProvider;
use Chiiya\LaravelIdentity\Session\SidManager;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Http\Controllers\AuthorizationController as PassportAuthorizationController;
use Laravel\Passport\Passport;
use Laravel\Passport\Scope;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class LaravelIdentityServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-identity')
            ->hasConfigFile('identity')
            ->hasViews('identity')
            ->hasRoutes(['web', 'api'])
            ->discoversMigrations();
    }

    public function packageRegistered(): void
    {
        // Swap Passport's authorization controller with ours.
        $this->app->bind(PassportAuthorizationController::class, AuthorizationController::class);

        // Mirror Passport's contextual StatefulGuard binding for our controller.
        $this->app->when(AuthorizationController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard(config('passport.guard')));

        // Swap Passport's auth code repository so the OIDC nonce reaches the id_token.
        $this->app->bind(PassportAuthCodeRepository::class, AuthCodeRepository::class);

        // Contracts → default implementations. Dedicated keys (EC / rotation) are
        // used when configured, otherwise the Passport RSA key backs every RS* alg.
        $this->app->singleton(KeyResolver::class, function ($app): KeyResolver {
            $keys = (array) config('identity.keys', []);

            return $keys === []
                ? $app->make(PassportKeyResolver::class)
                : new ConfigKeyResolver($keys);
        });
        $this->app->singleton(ScopeRegistrar::class, StandardScopeRegistrar::class);
        $this->app->singleton(SubjectIdentifierResolver::class, ClientAwareSubjectResolver::class);
        $this->app->singleton(SessionIdResolver::class, SidManager::class);
        $this->app->singleton(DiscoveryDocumentBuilder::class, DefaultDiscoveryBuilder::class);

        // Services.
        $this->app->singleton(JwtIssuer::class);
        $this->app->singleton(JwtValidator::class);
        $this->app->singleton(JwksBuilder::class);
        $this->app->singleton(NonceStore::class, fn ($app) => new NonceStore($app->make(Cache::class)));
        $this->app->singleton(ClaimAggregator::class);
        $this->app->singleton(UserProvider::class);
        $this->app->singleton(FrontChannelOrchestrator::class);
        $this->app->singleton(RpInitiatedLogoutValidator::class);
        $this->app->singleton(TokenIntrospector::class);
        $this->app->singleton(IdTokenResponseType::class);

        // Default claim provider (no-op; apps register their own).
        $this->app->tag(StandardClaimProvider::class, 'identity.claims');

        // Empty tags so the container does not fail when no listeners/providers are registered.
        $this->app->tag([], 'identity.logout_listeners');
    }

    public function packageBooted(): void
    {
        // Swap Passport's BearerTokenResponse so token endpoint responses include id_token.
        Passport::useAuthorizationServerResponseType($this->app->make(IdTokenResponseType::class));

        if (config('identity.register_openid_scope', true)) {
            $this->registerOidcScopes();
        }
    }

    /**
     * Register the OIDC scopes with Passport so they may be requested, without
     * clobbering any scopes the host application has already defined.
     */
    private function registerOidcScopes(): void
    {
        $registrar = $this->app->make(ScopeRegistrar::class);

        $existing = Passport::scopes()
            ->mapWithKeys(fn (Scope $scope): array => [$scope->id => $scope->description])
            ->all();

        $oidc = [];

        foreach ($registrar->all() as $scope) {
            $oidc[$scope] = $existing[$scope] ?? Str::headline($scope);
        }

        Passport::tokensCan([...$existing, ...$oidc]);
    }
}
