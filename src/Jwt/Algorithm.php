<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwt;

enum Algorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case PS256 = 'PS256';
    case PS384 = 'PS384';
    case PS512 = 'PS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';

    public function isRsa(): bool
    {
        return in_array($this, [self::RS256, self::RS384, self::RS512], strict: true);
    }

    public function isPss(): bool
    {
        return in_array($this, [self::PS256, self::PS384, self::PS512], strict: true);
    }

    public function isEc(): bool
    {
        return in_array($this, [self::ES256, self::ES384, self::ES512], strict: true);
    }
}
