<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwks;

class JwkEncoder
{
    public static function base64url(string $data): string
    {
        return mb_rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function encodeBignum(string $value): string
    {
        // OpenSSL returns the integer as a binary string; ensure it is treated unsigned.
        if (ord($value[0]) > 127) {
            $value = "\x00".$value;
        }

        return self::base64url($value);
    }
}
