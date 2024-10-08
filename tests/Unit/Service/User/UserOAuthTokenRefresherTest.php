<?php

declare(strict_types=1);

namespace Buddy\Repman\Tests\Unit\Service\User;

use Buddy\Repman\Service\User\UserOAuthTokenRefresher;
use Buddy\Repman\Service\User\UserOAuthTokenRefresher\AccessToken;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken as LeagueAccessToken;
use PHPUnit\Framework\TestCase;

class UserOAuthTokenRefresherTest extends TestCase
{
    public function testRefreshToken(): void
    {
        $oauth = $this->createMock(ClientRegistry::class);
        $provider = $this->createMock(AbstractProvider::class);
        $client = $this->createMock(OAuth2ClientInterface::class);
        $client->method('getOAuth2Provider')->willReturn($provider);
        $oauth->method('getClient')->willReturn($client);

        $provider->method('getAccessToken')->willReturnOnConsecutiveCalls(
            new LeagueAccessToken(['access_token' => 'new-token-1', 'refresh_token' => 'new-refresh-token-1']),
            new LeagueAccessToken(['access_token' => 'new-token-2']),
            new LeagueAccessToken(['access_token' => 'new-token-3', 'refresh_token' => 'new-refresh-token-3', 'expires_in' => 3600])
        );

        $refresher = new UserOAuthTokenRefresher($oauth);

        self::assertEquals(new AccessToken('new-token-1', 'new-refresh-token-1'), $refresher->refresh('github', 'refresh-token'));
        self::assertEquals(new AccessToken('new-token-2'), $refresher->refresh('github', 'refresh-token'));
        self::assertEquals(new AccessToken('new-token-3', 'new-refresh-token-3', (new \DateTimeImmutable())->setTimestamp(time() + 3600)), $refresher->refresh('github', 'refresh-token'));
    }
}
