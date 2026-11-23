<?php

declare(strict_types=1);

namespace Buddy\Repman\Tests\Unit\Service;

use Buddy\Repman\Query\Admin\ConfigQuery;
use Buddy\Repman\Service\Config;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class ConfigTest extends TestCase
{
    public function testOAuthRegistrationStaysEnabledWhenLocalRegistrationIsDisabled(): void
    {
        $query = $this->createMock(ConfigQuery::class);
        $query->method('findAll')->willReturn([
            'local_authentication' => 'login_only',
            'oauth_registration' => 'enabled',
        ]);

        $config = new Config($query, new ArrayAdapter());

        self::assertTrue($config->localLoginEnabled());
        self::assertFalse($config->localRegistrationEnabled());
        self::assertTrue($config->oauthRegistrationEnabled());
        self::assertTrue($config->userRegistrationEnabled());
    }

    public function testOAuthRegistrationStaysEnabledWhenLocalAuthenticationIsDisabled(): void
    {
        $query = $this->createMock(ConfigQuery::class);
        $query->method('findAll')->willReturn([
            'local_authentication' => 'disabled',
            'oauth_registration' => 'enabled',
        ]);

        $config = new Config($query, new ArrayAdapter());

        self::assertFalse($config->localLoginEnabled());
        self::assertFalse($config->localRegistrationEnabled());
        self::assertTrue($config->oauthRegistrationEnabled());
        self::assertTrue($config->userRegistrationEnabled());
    }

    public function testInvalidateClearsInMemoryValues(): void
    {
        $query = $this->createMock(ConfigQuery::class);
        $query->method('findAll')->willReturnOnConsecutiveCalls(
            [
                'local_authentication' => 'login_and_registration',
                'oauth_registration' => 'enabled',
            ],
            [
                'local_authentication' => 'login_only',
                'oauth_registration' => 'disabled',
            ]
        );

        $config = new Config($query, new ArrayAdapter());
        self::assertTrue($config->localRegistrationEnabled());
        self::assertTrue($config->oauthRegistrationEnabled());

        $config->invalidate();

        self::assertFalse($config->localRegistrationEnabled());
        self::assertFalse($config->oauthRegistrationEnabled());
    }
}
