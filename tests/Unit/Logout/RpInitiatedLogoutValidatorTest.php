<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Unit\Logout;

use Laravel\Passport\Client;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use Mindtwo\LaravelIdentity\Exceptions\InvalidIdTokenHint;
use Mindtwo\LaravelIdentity\Exceptions\InvalidRpLogoutRequest;
use Mindtwo\LaravelIdentity\Jwt\JwtValidator;
use Mindtwo\LaravelIdentity\Logout\RpInitiatedLogoutValidator;
use Mindtwo\LaravelIdentity\Tests\TestCase;
use Mockery\MockInterface;

class RpInitiatedLogoutValidatorTest extends TestCase
{
    public function test_throws_when_neither_id_token_hint_nor_client_id_provided(): void
    {
        $jwtValidator = $this->mock(JwtValidator::class);
        $validator = new RpInitiatedLogoutValidator($jwtValidator);

        $this->expectException(InvalidRpLogoutRequest::class);

        $validator->validate(null, null, null, null);
    }

    public function test_throws_when_id_token_hint_signature_is_invalid(): void
    {
        $jwtValidator = $this->mock(JwtValidator::class, function (MockInterface $mock): void {
            $mock->shouldReceive('parseAndVerify')
                ->andThrow(new InvalidIdTokenHint('bad signature'));
        });

        $validator = new RpInitiatedLogoutValidator($jwtValidator);

        $this->expectException(InvalidRpLogoutRequest::class);
        $this->expectExceptionMessage('Invalid id_token_hint');

        $validator->validate('bad.jwt.here', null, null, null);
    }

    public function test_post_logout_redirect_uri_is_rejected_when_client_cannot_validate_it(): void
    {
        // A plain Passport client (without HasOidcMetadata) has no registered
        // post_logout_redirect_uris, so an unverifiable URI must be rejected —
        // failing open would be an open redirect (RP-Initiated Logout 1.0 §3).
        $client = Client::factory()->create();

        $token = new Plain(
            new DataSet([], ''),
            new DataSet([
                'iss' => config('app.url'),
                'sub' => 'user-123',
                'aud' => [(string) $client->getKey()],
            ], ''),
            new Signature('', ''),
        );

        $jwtValidator = $this->mock(JwtValidator::class, function (MockInterface $mock) use ($token): void {
            $mock->shouldReceive('parseAndVerify')->andReturn($token);
        });

        $validator = new RpInitiatedLogoutValidator($jwtValidator);

        $this->expectException(InvalidRpLogoutRequest::class);
        $this->expectExceptionMessage('post_logout_redirect_uri');

        $validator->validate('some.valid.token', 'https://evil.example.com/steal', null, null);
    }

    public function test_state_is_preserved_in_logout_request(): void
    {
        $client = Client::factory()->create();

        $token = new Plain(
            new DataSet([], ''),
            new DataSet([
                'iss' => config('app.url'),
                'sub' => 'user-123',
                'aud' => [(string) $client->getKey()],
            ], ''),
            new Signature('', ''),
        );

        $jwtValidator = $this->mock(JwtValidator::class, function (MockInterface $mock) use ($token): void {
            $mock->shouldReceive('parseAndVerify')->andReturn($token);
        });

        $validator = new RpInitiatedLogoutValidator($jwtValidator);
        $result = $validator->validate('some.valid.token', null, 'my-state', null);

        $this->assertSame('my-state', $result->state);
    }
}
