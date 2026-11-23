<?php

declare(strict_types=1);

namespace Buddy\Repman\Tests\Integration\Security;

use Buddy\Repman\Security\GitHubAuthenticator;
use Buddy\Repman\Security\UserProvider;
use Buddy\Repman\Service\Integration\GitHubApi;
use Buddy\Repman\Tests\Doubles\GitHubOAuth;
use Buddy\Repman\Tests\Integration\IntegrationTestCase;
use Github\Exception\ApiLimitExceedException;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

final class GitHubAuthenticatorTest extends IntegrationTestCase
{
    public function testRedirectToLoginWithFlashOnFailure(): void
    {
        $response = $this->container()->get(GitHubAuthenticator::class)->onAuthenticationFailure(
            $request = $this->createRequestWithSession(),
            new UserNotFoundException()
        );

        self::assertTrue($response->isRedirection());

        $session = $request->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertTrue($session->getFlashBag()->has('danger'));
    }

    public function testThrowExceptionIfUserWasNotFoundWhenOAuthRegistrationIsDisabled(): void
    {
        $this->fixtures->changeConfig('oauth_registration', 'disabled');
        GitHubOAuth::mockTokenResponse('some@buddy.works', $this->container());
        $request = $this->createRequestWithSession();
        $request->attributes->set('_route', 'login_github_check');
        $request->query->set('code', '123');
        $this->container()->get(ClientRegistry::class)->getClient('github')->setAsStateless();

        $this->expectException(UserNotFoundException::class);

        $this->container()->get(GitHubAuthenticator::class)->authenticate($request);
    }

    public function testCreateUserOnLoginWhenLocalRegistrationIsDisabledAndOAuthRegistrationIsEnabled(): void
    {
        $this->fixtures->changeConfig('local_authentication', 'login_only');
        $this->fixtures->changeConfig('oauth_registration', 'enabled');
        GitHubOAuth::mockTokenResponse($email = 'new-github@example.com', $this->container());
        $request = $this->createRequestWithSession();
        $request->attributes->set('_route', 'login_github_check');
        $request->query->set('code', '123');
        $this->container()->get(ClientRegistry::class)->getClient('github')->setAsStateless();

        $passport = $this->container()->get(GitHubAuthenticator::class)->authenticate($request);

        $badge = $passport->getBadge(UserBadge::class);
        self::assertInstanceOf(UserBadge::class, $badge);
        self::assertSame($email, $badge->getUserIdentifier());
        self::assertTrue($this->container()->get(UserProvider::class)->emailExist($email));
    }

    public function testThrowCustomExceptionOnGitHubApiError(): void
    {
        GitHubOAuth::mockTokenResponse('some@buddy.works', $this->container());
        $this->container()->get(GitHubApi::class)->setExceptionOnNextCall(new ApiLimitExceedException(5000));
        $request = $this->createRequestWithSession();
        $request->attributes->set('_route', 'login_github_check');
        $request->query->set('code', '123');
        $this->container()->get(ClientRegistry::class)->getClient('github')->setAsStateless();

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('You have reached GitHub hourly limit! Actual limit is: 5000');

        $this->container()->get(GitHubAuthenticator::class)->authenticate($request);
    }
}
