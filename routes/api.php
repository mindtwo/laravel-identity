<?php declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Laravel\Passport\Http\Middleware\CheckToken;
use Mindtwo\LaravelIdentity\Http\Controllers\DiscoveryController;
use Mindtwo\LaravelIdentity\Http\Controllers\IntrospectionController;
use Mindtwo\LaravelIdentity\Http\Controllers\JwksController;
use Mindtwo\LaravelIdentity\Http\Controllers\UserInfoController;
use Mindtwo\LaravelIdentity\Http\Middleware\AuthenticateClient;

Route::get('/.well-known/openid-configuration', [DiscoveryController::class, 'show'])
    ->name('identity.discovery');

Route::get('/.well-known/jwks.json', [JwksController::class, 'show'])
    ->name('identity.jwks');

Route::match(['get', 'post'], '/oauth/userinfo', [UserInfoController::class, 'show'])
    ->middleware(['auth:api', CheckToken::class.':openid'])
    ->name('identity.userinfo');

Route::post('/oauth/introspect', [IntrospectionController::class, 'introspect'])
    ->middleware(AuthenticateClient::class)
    ->name('identity.introspect');
