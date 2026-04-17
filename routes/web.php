<?php declare(strict_types=1);

use Chiiya\LaravelIdentity\Http\Controllers\EndSessionController;
use Chiiya\LaravelIdentity\Http\Controllers\FrontChannelLogoutController;
use Illuminate\Support\Facades\Route;

Route::middleware(['web', 'auth'])->group(function (): void {
    Route::match(['get', 'post'], '/oauth/logout', [EndSessionController::class, 'show'])
        ->name('identity.end_session');

    Route::get('/oauth/logout/frontchannel', [FrontChannelLogoutController::class, 'show'])
        ->name('identity.frontchannel_logout');
});
