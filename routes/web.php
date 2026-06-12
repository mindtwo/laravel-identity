<?php declare(strict_types=1);

use Chiiya\LaravelIdentity\Http\Controllers\EndSessionController;
use Chiiya\LaravelIdentity\Http\Controllers\FrontChannelLogoutController;
use Illuminate\Support\Facades\Route;

// The end session endpoint must be reachable without an active session so that
// RP-initiated logout can honor id_token_hint / post_logout_redirect_uri. GET may
// render the confirmation screen; POST is the confirmed logout. Both live at the
// same path, so confirmation forms simply POST back to route('identity.end_session').
Route::get('/oauth/logout', [EndSessionController::class, 'show'])
    ->middleware('web')
    ->name('identity.end_session');

Route::post('/oauth/logout', [EndSessionController::class, 'logout'])
    ->middleware('web')
    ->name('identity.end_session.confirm');

Route::get('/oauth/logout/frontchannel', [FrontChannelLogoutController::class, 'show'])
    ->middleware(['web', 'auth'])
    ->name('identity.frontchannel_logout');
