<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Session;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id The `sid` claim value.
 * @property string|int $user_id
 * @property string $client_id
 * @property string $laravel_session_id
 * @property Carbon|null $auth_time
 * @property Carbon $created_at
 * @property Carbon $last_seen_at
 * @property Carbon|null $revoked_at
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
        'auth_time',
        'created_at',
        'last_seen_at',
        'revoked_at',
    ];
    protected $casts = [
        'auth_time' => 'datetime',
        'created_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];
}
