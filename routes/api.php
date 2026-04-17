<?php declare(strict_types=1);

use Chiiya\LaravelIdentity\Http\Controllers\DiscoveryController;
use Chiiya\LaravelIdentity\Http\Controllers\IntrospectionController;
use Chiiya\LaravelIdentity\Http\Controllers\JwksController;
use Chiiya\LaravelIdentity\Http\Controllers\UserInfoController;
use Chiiya\LaravelIdentity\Http\Middleware\AuthenticateClient;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Http\Middleware\CheckToken;

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
