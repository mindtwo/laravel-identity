<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class IntrospectRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'token' => ['required', 'string'],
            'token_type_hint' => ['nullable', 'string', 'in:access_token,refresh_token'],
        ];
    }
}
