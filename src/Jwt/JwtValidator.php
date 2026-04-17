<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwt;

use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Exceptions\InvalidIdTokenHint;
use Illuminate\Support\Facades\Log;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcSha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as EcSha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as EcSha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Pss\Sha256 as PssSha256;
use Lcobucci\JWT\Signer\Rsa\Pss\Sha384 as PssSha384;
use Lcobucci\JWT\Signer\Rsa\Pss\Sha512 as PssSha512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;

class JwtValidator
{
    public function __construct(
        private readonly KeyResolver $keyResolver,
    ) {}

    /**
     * Parse and signature-verify an id_token_hint.
     *
     * @throws InvalidIdTokenHint
     */
    public function parseAndVerify(string $token): Plain
    {
        try {
            $parsed = (new Parser(new JoseEncoder()))->parse($token);
        } catch (\Throwable $e) {
            throw new InvalidIdTokenHint('Failed to parse id_token_hint: '.$e->getMessage(), previous: $e);
        }

        if (! $parsed instanceof Plain) {
            throw new InvalidIdTokenHint('id_token_hint is not a plain JWT.');
        }

        $kid = $parsed->headers()->has('kid') ? $parsed->headers()->get('kid') : null;

        if ($kid !== null) {
            $material = $this->keyResolver->byKid((string) $kid);

            if ($material === null) {
                throw new InvalidIdTokenHint("Unknown key ID: {$kid}");
            }

            $this->verifySignature($parsed, $material);
        } else {
            // Tolerate missing kid by trying all keys; log deprecation so users can fix.
            Log::warning('identity: id_token_hint is missing a kid header — unable to select key precisely.');
            $verified = false;

            foreach ($this->keyResolver->all() as $material) {
                try {
                    $this->verifySignature($parsed, $material);
                    $verified = true;
                    break;
                } catch (InvalidIdTokenHint) {
                    continue;
                }
            }

            if (! $verified) {
                throw new InvalidIdTokenHint('Signature verification failed for id_token_hint (no valid key found).');
            }
        }

        return $parsed;
    }

    /**
     * @throws InvalidIdTokenHint
     */
    private function verifySignature(Plain $token, KeyMaterial $material): void
    {
        $signer = match ($material->algorithm) {
            Algorithm::RS256 => new RsaSha256(),
            Algorithm::RS384 => new RsaSha384(),
            Algorithm::RS512 => new RsaSha512(),
            Algorithm::PS256 => new PssSha256(),
            Algorithm::PS384 => new PssSha384(),
            Algorithm::PS512 => new PssSha512(),
            Algorithm::ES256 => EcSha256::create(),
            Algorithm::ES384 => EcSha384::create(),
            Algorithm::ES512 => EcSha512::create(),
        };

        $validator = new Validator();
        $key = InMemory::plainText($material->publicKey);

        if (! $validator->validate($token, new SignedWith($signer, $key))) {
            throw new InvalidIdTokenHint('id_token_hint signature is invalid.');
        }
    }
}
