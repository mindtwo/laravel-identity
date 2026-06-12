<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Unit\Logout;

use Chiiya\LaravelIdentity\Exceptions\InvalidIdTokenHint;
use Chiiya\LaravelIdentity\Exceptions\InvalidRpLogoutRequest;
use Chiiya\LaravelIdentity\Jwt\JwtValidator;
use Chiiya\LaravelIdentity\Logout\RpInitiatedLogoutValidator;
use Chiiya\LaravelIdentity\Tests\TestCase;
use Laravel\Passport\Client;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
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
