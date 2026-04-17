<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class EndSessionRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'id_token_hint' => ['nullable', 'string'],
            'client_id' => ['nullable', 'string'],
            'post_logout_redirect_uri' => ['nullable', 'url'],
            'state' => ['nullable', 'string'],
        ];
    }
}
