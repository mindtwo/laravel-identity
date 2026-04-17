<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

use DateTimeImmutable;

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

    public static function fromRequest(\Illuminate\Http\Request $request, DateTimeImmutable $authTime): self
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
