<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Tests\Feature;

use Chiiya\LaravelIdentity\Tests\TestCase;

class DiscoveryEndpointTest extends TestCase
{
    public function test_returns_required_openid_connect_fields(): void
    {
        $response = $this->getJson('/.well-known/openid-configuration');

        $response->assertOk();
        $response->assertJsonStructure([
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
            'response_types_supported',
            'subject_types_supported',
            'id_token_signing_alg_values_supported',
        ]);
    }

    public function test_issuer_matches_app_url(): void
    {
        $response = $this->getJson('/.well-known/openid-configuration');

        $response->assertJsonPath('issuer', config('app.url'));
    }

    public function test_response_types_supported_contains_code(): void
    {
        $response = $this->getJson('/.well-known/openid-configuration');

        $this->assertContains('code', $response->json('response_types_supported'));
    }

    public function test_frontchannel_logout_is_advertised(): void
    {
        $response = $this->getJson('/.well-known/openid-configuration');

        $response->assertJsonPath('frontchannel_logout_supported', true);
    }

    public function test_unsupported_parameters_are_advertised_as_false(): void
    {
        $response = $this->getJson('/.well-known/openid-configuration');

        // These must be present and explicitly false — they default to true per
        // Discovery 1.0, so omitting them would wrongly imply support.
        $response->assertJsonPath('request_parameter_supported', false);
        $response->assertJsonPath('request_uri_parameter_supported', false);
        $response->assertJsonPath('claims_parameter_supported', false);
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();
        $this->artisan('passport:keys', ['--force' => true])->run();
    }
}
