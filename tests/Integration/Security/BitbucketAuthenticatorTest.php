<?php

declare(strict_types=1);

namespace Buddy\Repman\Tests\Integration\Security;

use Bitbucket\Exception\ApiLimitExceededException;
use Buddy\Repman\Security\BitbucketAuthenticator;
use Buddy\Repman\Security\UserProvider;
use Buddy\Repman\Service\Integration\BitbucketApi;
use Buddy\Repman\Tests\Doubles\BitbucketOAuth;
use Buddy\Repman\Tests\Integration\IntegrationTestCase;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

final class BitbucketAuthenticatorTest extends IntegrationTestCase
{
    public function testRedirectToLoginWithFlashOnFailure(): void
    {
        $response = $this->container()->get(BitbucketAuthenticator::class)->onAuthenticationFailure(
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
        BitbucketOAuth::mockAccessTokenResponse('some@buddy.works', $this->container());
        $this->expectException(UserNotFoundException::class);

        $request = $this->createRequestWithSession();
        $request->attributes->set('_route', 'login_bitbucket_check');
        $request->query->set('code', '123');
        $this->container()->get(ClientRegistry::class)->getClient('bitbucket')->setAsStateless();

        $this->container()->get(BitbucketAuthenticator::class)->authenticate($request);
    }

    public function testCreateUserOnLoginWhenLocalRegistrationIsDisabledAndOAuthRegistrationIsEnabled(): void
    {
        $this->fixtures->changeConfig('local_authentication', 'login_only');
        $this->fixtures->changeConfig('oauth_registration', 'enabled');
        BitbucketOAuth::mockAccessTokenResponse($email = 'new-bitbucket@example.com', $this->container());

        $request = $this->createRequestWithSession();
        $request->attributes->set('_route', 'login_bitbucket_check');
        $request->query->set('code', '123');
        $this->container()->get(ClientRegistry::class)->getClient('bitbucket')->setAsStateless();

        $passport = $this->container()->get(BitbucketAuthenticator::class)->authenticate($request);

        $badge = $passport->getBadge(UserBadge::class);
        self::assertInstanceOf(UserBadge::class, $badge);
        self::assertSame($email, $badge->getUserIdentifier());
        self::assertTrue($this->container()->get(UserProvider::class)->emailExist($email));
    }

    public function testThrowCustomExceptionOnBitbucketApiError(): void
    {
        BitbucketOAuth::mockAccessTokenResponse('some@buddy.works', $this->container());
        $this->container()->get(BitbucketApi::class)->setExceptionOnNextCall(new ApiLimitExceededException('Message from Bitbucket about API limits'));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Message from Bitbucket about API limits');

        $request = $this->createRequestWithSession();
        $request->attributes->set('_route', 'login_bitbucket_check');
        $request->query->set('code', '123');
        $this->container()->get(ClientRegistry::class)->getClient('bitbucket')->setAsStateless();

        $this->container()->get(BitbucketAuthenticator::class)->authenticate($request);
    }
}
