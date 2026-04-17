<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Session;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id              The `sid` claim value.
 * @property string|int $user_id
 * @property string $client_id
 * @property string $laravel_session_id
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $last_seen_at
 * @property \Carbon\Carbon|null $revoked_at
 */
class OidcSession extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $table = 'oidc_sessions';

    protected $fillable = [
        'user_id',
        'client_id',
        'laravel_session_id',
        'created_at',
        'last_seen_at',
    ];

    protected $casts = [
        'created_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];
}
