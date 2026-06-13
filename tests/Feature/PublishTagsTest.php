<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Tests\Feature;

use Illuminate\Support\ServiceProvider;
use Mindtwo\LaravelIdentity\Tests\TestCase;

class PublishTagsTest extends TestCase
{
    public function test_documented_publish_tags_are_registered(): void
    {
        $groups = array_keys(ServiceProvider::$publishGroups);

        // These are the exact tags documented in the README. spatie derives them
        // from the package short name (laravel-identity → identity), so they must
        // stay in sync or `vendor:publish` fails with "Unable to locate resources".
        $this->assertContains('identity-config', $groups);
        $this->assertContains('identity-migrations', $groups);
    }
}
