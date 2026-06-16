<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity;

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Http\Controllers\AuthorizationController as PassportAuthorizationController;
use Laravel\Passport\Passport;
use Laravel\Passport\Scope;
use Mindtwo\LaravelIdentity\Bridge\AuthCodeRepository;
use Mindtwo\LaravelIdentity\Contracts\DiscoveryDocumentBuilder;
use Mindtwo\LaravelIdentity\Contracts\KeyResolver;
use Mindtwo\LaravelIdentity\Contracts\ScopeRegistrar;
use Mindtwo\LaravelIdentity\Contracts\SessionIdResolver;
use Mindtwo\LaravelIdentity\Contracts\SubjectIdentifierResolver;
use Mindtwo\LaravelIdentity\Discovery\DefaultDiscoveryBuilder;
use Mindtwo\LaravelIdentity\Http\Controllers\AuthorizationController;
use Mindtwo\LaravelIdentity\Introspection\TokenIntrospector;
use Mindtwo\LaravelIdentity\Jwks\JwksBuilder;
use Mindtwo\LaravelIdentity\Jwt\JwtIssuer;
use Mindtwo\LaravelIdentity\Jwt\JwtValidator;
use Mindtwo\LaravelIdentity\Jwt\KeyResolvers\ConfigKeyResolver;
use Mindtwo\LaravelIdentity\Jwt\KeyResolvers\PassportKeyResolver;
use Mindtwo\LaravelIdentity\Logout\FrontChannelOrchestrator;
use Mindtwo\LaravelIdentity\Logout\RpInitiatedLogoutValidator;
use Mindtwo\LaravelIdentity\Oidc\ClaimAggregator;
use Mindtwo\LaravelIdentity\Oidc\IdTokenResponseType;
use Mindtwo\LaravelIdentity\Oidc\NonceStore;
use Mindtwo\LaravelIdentity\Oidc\Scopes\StandardClaimProvider;
use Mindtwo\LaravelIdentity\Oidc\Scopes\StandardScopeRegistrar;
use Mindtwo\LaravelIdentity\Oidc\SubjectResolvers\ClientAwareSubjectResolver;
use Mindtwo\LaravelIdentity\Oidc\UserProvider;
use Mindtwo\LaravelIdentity\Session\SidManager;
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
        // Expose the front-channel logout mechanism as <x-identity::front-channel-logout>
        // so apps can embed it in their own page instead of reimplementing the iframes.
        Blade::anonymousComponentNamespace('identity::components', 'identity');

        // Swap Passport's BearerTokenResponse so token endpoint responses include id_token.
        Passport::useAuthorizationServerResponseType($this->app->make(IdTokenResponseType::class));

        // Deferred until every provider has booted: host apps register custom scopes
        // (via Identity::registerScope() or the ScopeRegistrar directly) from their own
        // providers, and we cannot assume they boot before us. Running here guarantees
        // the registry is complete before it is snapshotted into Passport.
        $this->app->booted(function (): void {
            $this->applyCustomScopes();

            if (config('identity.register_openid_scope', true)) {
                $this->registerOidcScopes();
            }
        });
    }

    /**
     * Flush scopes buffered via Identity::registerScope() into the ScopeRegistrar.
     * The registrar backs discovery and claim filtering, so this runs regardless of
     * the register_openid_scope toggle (which only governs the Passport snapshot).
     */
    private function applyCustomScopes(): void
    {
        $registrar = $this->app->make(ScopeRegistrar::class);

        foreach (Identity::$scopes as $scope => $claims) {
            $registrar->register($scope, $claims);
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
