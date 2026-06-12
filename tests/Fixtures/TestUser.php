<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Fixtures;

use Chiiya\LaravelIdentity\Contracts\ClaimProvider;
use DateTimeImmutable;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

class TestUser extends Authenticatable implements ClaimProvider, OAuthenticatable
{
    use HasApiTokens;
    protected $table = 'users';
    protected $fillable = ['name', 'email', 'password'];
    protected $hidden = ['password', 'remember_token'];

    protected DateTimeImmutable $authTime;

    public function getAuthTime(): DateTimeImmutable
    {
        return $this->authTime ?? new DateTimeImmutable;
    }

    public function setAuthTime(DateTimeImmutable $time): void
    {
        $this->authTime = $time;
    }

    public function getClaims(OAuthenticatable $user, array $scopes): array
    {
        return array_filter([
            'name' => $this->name,
            'email' => $this->email,
            'email_verified' => true,
        ]);
    }

    public function handles(): array
    {
        return ['profile', 'email'];
    }
}
