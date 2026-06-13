<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc;

use DateTimeImmutable;
use Illuminate\Http\Request;

readonly class AuthRequestContext
{
    public function __construct(
        public ?string $nonce,
        public ?int $maxAge,
        public ?string $prompt,
        public ?string $uiLocales,
        public ?string $acrValues,
        public ?string $loginHint,
        public ?string $idTokenHint,
        public DateTimeImmutable $authTime,
    ) {}

    public static function fromRequest(Request $request, DateTimeImmutable $authTime): self
    {
        return new self(
            nonce: $request->input('nonce'),
            maxAge: $request->filled('max_age') ? (int) $request->input('max_age') : null,
            prompt: $request->input('prompt'),
            uiLocales: $request->input('ui_locales'),
            acrValues: $request->input('acr_values'),
            loginHint: $request->input('login_hint'),
            idTokenHint: $request->input('id_token_hint'),
            authTime: $authTime,
        );
    }
}
