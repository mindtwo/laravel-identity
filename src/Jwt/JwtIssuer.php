<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Jwt;

use Chiiya\LaravelIdentity\Contracts\KeyResolver;
use Chiiya\LaravelIdentity\Oidc\IdTokenContext;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcSha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as EcSha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as EcSha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;
use Lcobucci\JWT\Token\Builder;

class JwtIssuer
{
    public function __construct(
        private readonly KeyResolver $keyResolver,
    ) {}

    public function issueIdToken(IdTokenContext $context): string
    {
        $material = $this->keyResolver->current($context->algorithm);
        $signer = $this->signerFor($material->algorithm);
        $signingKey = InMemory::plainText($material->privateKey);

        $builder = Builder::new(new JoseEncoder, ChainedFormatter::default())
            ->withHeader('kid', $material->kid)
            ->issuedBy($this->issuer())
            ->permittedFor((string) $context->client->getKey())
            ->relatedTo($context->subject)
            ->issuedAt($context->issuedAt)
            ->expiresAt($context->expiresAt)
            ->withClaim('auth_time', $context->authTime->getTimestamp());

        if ($context->nonce !== null) {
            $builder = $builder->withClaim('nonce', $context->nonce);
        }

        if ($context->sid !== null) {
            $builder = $builder->withClaim('sid', $context->sid);
        }

        foreach ($context->claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken($signer, $signingKey)->toString();
    }

    public function issuer(): string
    {
        return config('identity.issuer') ?: config('app.url');
    }

    private function signerFor(Algorithm $algorithm): Signer
    {
        return match ($algorithm) {
            Algorithm::RS256 => new RsaSha256,
            Algorithm::RS384 => new RsaSha384,
            Algorithm::RS512 => new RsaSha512,
            Algorithm::ES256 => EcSha256::create(),
            Algorithm::ES384 => EcSha384::create(),
            Algorithm::ES512 => EcSha512::create(),
        };
    }
}
