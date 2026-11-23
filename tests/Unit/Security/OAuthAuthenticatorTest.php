<?php

declare(strict_types=1);

namespace Buddy\Repman\Tests\Unit\Security;

use Buddy\Repman\Message\User\CreateOAuthUser;
use Buddy\Repman\Query\Admin\ConfigQuery;
use Buddy\Repman\Repository\UserRepository;
use Buddy\Repman\Security\BitbucketAuthenticator;
use Buddy\Repman\Security\BuddyAuthenticator;
use Buddy\Repman\Security\GitHubAuthenticator;
use Buddy\Repman\Security\GitLabAuthenticator;
use Buddy\Repman\Security\LoginFormAuthenticator;
use Buddy\Repman\Security\UserChecker;
use Buddy\Repman\Security\UserGuardHelper;
use Buddy\Repman\Security\UserProvider;
use Buddy\Repman\Service\Config;
use Buddy\Repman\Service\Integration\BitbucketApi;
use Buddy\Repman\Service\Integration\BuddyApi;
use Buddy\Repman\Service\Integration\GitHubApi;
use Doctrine\DBAL\Connection;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Exception\MissingAuthorizationCodeException;
use KnpU\OAuth2ClientBundle\Security\Exception\NoAuthCodeAuthenticationException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Omines\OAuth2\Client\Provider\GitlabResourceOwner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

final class OAuthAuthenticatorTest extends TestCase
{
    public function testLoginCreatesNewUserWhenLocalRegistrationIsDisabledAndOAuthRegistrationIsEnabled(): void
    {
        $email = 'new-github@example.com';
        $messageBus = $this->expectCreateUserDispatch($email);
        $gitHubApi = $this->createMock(GitHubApi::class);
        $gitHubApi->method('primaryEmail')->willReturn(' '.$email.' ');

        $authenticator = new GitHubAuthenticator(
            $this->createClientRegistry('github'),
            $gitHubApi,
            $this->createRouter(),
            $this->createUserProvider($email, false, true),
            $this->createConfig('login_only', 'enabled'),
            $messageBus
        );

        $session = new Session(new MockArraySessionStorage());
        $request = $this->createRequest('login_github_check', $session);
        $passport = $authenticator->authenticate($request);

        $badge = $passport->getBadge(UserBadge::class);
        self::assertInstanceOf(UserBadge::class, $badge);
        self::assertSame($email, $badge->getUserIdentifier());

        $response = $authenticator->onAuthenticationSuccess($request, $this->createMock(TokenInterface::class), 'main');
        self::assertSame('/organization_create?origin=github', $response->headers->get('location'));
        self::assertSame(
            ['Your account has been created. Please create a new organization.'],
            $session->getFlashBag()->get('success')
        );
    }

    public function testLoginCreatesNewUserWhenLocalAuthenticationIsDisabledAndOAuthRegistrationIsEnabled(): void
    {
        $email = 'new-gitlab@example.com';
        $messageBus = $this->expectCreateUserDispatch($email);

        $token = new AccessToken(['access_token' => 'secret']);
        $client = $this->createMock(OAuth2ClientInterface::class);
        $client->method('getAccessToken')->willReturn($token);
        $client->method('fetchUserFromToken')->willReturn(new GitlabResourceOwner(['email' => $email], $token));

        $registry = $this->createMock(ClientRegistry::class);
        $registry->method('getClient')->with('gitlab')->willReturn($client);

        $authenticator = new GitLabAuthenticator(
            $registry,
            $this->createRouter(),
            $this->createUserProvider($email, false, true),
            $this->createConfig('disabled', 'enabled'),
            $messageBus
        );

        $request = $this->createRequest('login_gitlab_check');
        $authenticator->authenticate($request);

        $response = $authenticator->onAuthenticationSuccess($request, $this->createMock(TokenInterface::class), 'main');
        self::assertSame('/organization_create?origin=gitlab', $response->headers->get('location'));
    }

    public function testLoginThrowsUserNotFoundWhenOAuthRegistrationIsDisabled(): void
    {
        $messageBus = $this->createMock(MessageBusInterface::class);
        $messageBus->expects(self::never())->method('dispatch');

        $gitHubApi = $this->createMock(GitHubApi::class);
        $gitHubApi->method('primaryEmail')->willReturn('missing@example.com');

        $authenticator = new GitHubAuthenticator(
            $this->createClientRegistry('github'),
            $gitHubApi,
            $this->createRouter(),
            $this->createUserProvider('missing@example.com', false, false),
            $this->createConfig('login_only', 'disabled'),
            $messageBus
        );

        $this->expectException(UserNotFoundException::class);

        $authenticator->authenticate($this->createRequest('login_github_check'));
    }

    public function testLoginAuthenticatesExistingUserWithoutCreatingDuplicateWhenOAuthRegistrationIsDisabled(): void
    {
        $email = 'existing@example.com';
        $messageBus = $this->createMock(MessageBusInterface::class);
        $messageBus->expects(self::never())->method('dispatch');

        $gitHubApi = $this->createMock(GitHubApi::class);
        $gitHubApi->method('primaryEmail')->willReturn($email);

        $authenticator = new GitHubAuthenticator(
            $this->createClientRegistry('github'),
            $gitHubApi,
            $this->createRouter(),
            $this->createUserProvider($email, true, true),
            $this->createConfig('disabled', 'disabled'),
            $messageBus
        );

        $request = $this->createRequest('login_github_check');
        $passport = $authenticator->authenticate($request);

        $badge = $passport->getBadge(UserBadge::class);
        self::assertInstanceOf(UserBadge::class, $badge);
        self::assertSame($email, $badge->getUserIdentifier());

        $response = $authenticator->onAuthenticationSuccess($request, $this->createMock(TokenInterface::class), 'main');
        self::assertSame('/index', $response->headers->get('location'));
    }

    public function testSupportsOnlyLoginCheckRoute(): void
    {
        $authenticator = new GitHubAuthenticator(
            $this->createClientRegistry('github'),
            $this->createMock(GitHubApi::class),
            $this->createRouter(),
            $this->createUserProvider('user@example.com', true, true),
            $this->createConfig('login_only', 'enabled'),
            $this->createMock(MessageBusInterface::class)
        );

        self::assertTrue($authenticator->supports($this->createRequest('login_github_check')));
        self::assertFalse($authenticator->supports($this->createRequest('register_github_check')));
    }

    public function testFetchAccessTokenMissingCodePreservesAuthFailureMessage(): void
    {
        $client = $this->createMock(OAuth2ClientInterface::class);
        $client->method('getAccessToken')->willThrowException(new MissingAuthorizationCodeException());

        $registry = $this->createMock(ClientRegistry::class);
        $registry->method('getClient')->with('github')->willReturn($client);

        $authenticator = new GitHubAuthenticator(
            $registry,
            $this->createMock(GitHubApi::class),
            $this->createRouter(),
            $this->createUserProvider('user@example.com', false, false),
            $this->createConfig('login_only', 'enabled'),
            $this->createMock(MessageBusInterface::class)
        );

        $session = new Session(new MockArraySessionStorage());
        $request = $this->createRequest('login_github_check', $session);

        try {
            $authenticator->authenticate($request);
            self::fail('Expected NoAuthCodeAuthenticationException');
        } catch (NoAuthCodeAuthenticationException $exception) {
            $response = $authenticator->onAuthenticationFailure($request, $exception);
            self::assertSame('/app_login', $response->headers->get('location'));
            self::assertSame(
                ['Authentication failed! Did you authorize our app?'],
                $session->getFlashBag()->get('danger')
            );
        }
    }

    public function testGitHubRuntimeExceptionIsConvertedToAuthenticationException(): void
    {
        $gitHubApi = $this->createMock(GitHubApi::class);
        $gitHubApi->method('primaryEmail')->willThrowException(new \RuntimeException('Primary e-mail not found.'));

        $authenticator = new GitHubAuthenticator(
            $this->createClientRegistry('github'),
            $gitHubApi,
            $this->createRouter(),
            $this->createUserProvider('user@example.com', false, false),
            $this->createConfig('login_only', 'enabled'),
            $this->createMock(MessageBusInterface::class)
        );

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Primary e-mail not found.');

        $authenticator->authenticate($this->createRequest('login_github_check'));
    }

    public function testGitLabNullEmailIsConvertedToAuthenticationException(): void
    {
        $token = new AccessToken(['access_token' => 'secret']);
        $client = $this->createMock(OAuth2ClientInterface::class);
        $client->method('getAccessToken')->willReturn($token);
        $client->method('fetchUserFromToken')->willReturn(new GitlabResourceOwner(['email' => null], $token));

        $registry = $this->createMock(ClientRegistry::class);
        $registry->method('getClient')->with('gitlab')->willReturn($client);

        $authenticator = new GitLabAuthenticator(
            $registry,
            $this->createRouter(),
            $this->createUserProvider('user@example.com', false, false),
            $this->createConfig('login_only', 'enabled'),
            $this->createMock(MessageBusInterface::class)
        );

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Primary e-mail not found.');

        $authenticator->authenticate($this->createRequest('login_gitlab_check'));
    }

    public function testGitLabIdentityProviderErrorFromTokenExchangeIsConvertedToCustomAuthException(): void
    {
        $client = $this->createMock(OAuth2ClientInterface::class);
        $client->method('getAccessToken')->willThrowException(new IdentityProviderException('Too Many Requests', 429, ''));

        $registry = $this->createMock(ClientRegistry::class);
        $registry->method('getClient')->with('gitlab')->willReturn($client);

        $authenticator = new GitLabAuthenticator(
            $registry,
            $this->createRouter(),
            $this->createUserProvider('user@example.com', false, false),
            $this->createConfig('login_only', 'enabled'),
            $this->createMock(MessageBusInterface::class)
        );

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Too Many Requests');

        $authenticator->authenticate($this->createRequest('login_gitlab_check'));
    }

    public function testBitbucketRuntimeExceptionIsConvertedToAuthenticationException(): void
    {
        $bitbucketApi = $this->createMock(BitbucketApi::class);
        $bitbucketApi->method('primaryEmail')->willThrowException(new \RuntimeException('Primary e-mail not found.'));

        $authenticator = new BitbucketAuthenticator(
            $this->createClientRegistry('bitbucket'),
            $bitbucketApi,
            $this->createRouter(),
            $this->createUserProvider('user@example.com', false, false),
            $this->createConfig('login_only', 'enabled'),
            $this->createMock(MessageBusInterface::class)
        );

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Primary e-mail not found.');

        $authenticator->authenticate($this->createRequest('login_bitbucket_check'));
    }

    public function testBuddyRuntimeExceptionIsConvertedToAuthenticationException(): void
    {
        $buddyApi = $this->createMock(BuddyApi::class);
        $buddyApi->method('primaryEmail')->willThrowException(new \RuntimeException('Primary e-mail not found.'));

        $authenticator = new BuddyAuthenticator(
            $this->createClientRegistry('buddy'),
            $buddyApi,
            $this->createRouter(),
            $this->createUserProvider('user@example.com', false, false),
            $this->createConfig('login_only', 'enabled'),
            $this->createMock(MessageBusInterface::class)
        );

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Primary e-mail not found.');

        $authenticator->authenticate($this->createRequest('login_buddy_check'));
    }

    public function testOnAuthenticationSuccessRedirectsNewUserWithOrganizationInvitationToken(): void
    {
        $email = 'invited@example.com';
        $gitHubApi = $this->createMock(GitHubApi::class);
        $gitHubApi->method('primaryEmail')->willReturn($email);

        $authenticator = new GitHubAuthenticator(
            $this->createClientRegistry('github'),
            $gitHubApi,
            $this->createRouter(),
            $this->createUserProvider($email, false, true),
            $this->createConfig('login_only', 'enabled'),
            $this->expectCreateUserDispatch($email)
        );

        $session = new Session(new MockArraySessionStorage());
        $session->set('organization-token', 'invite-token-123');
        $request = $this->createRequest('login_github_check', $session);
        $authenticator->authenticate($request);

        $response = $authenticator->onAuthenticationSuccess($request, $this->createMock(TokenInterface::class), 'main');
        self::assertSame('/organization_accept_invitation?token=invite-token-123', $response->headers->get('location'));
        self::assertFalse($session->has('organization-token'));
    }

    public function testOnAuthenticationSuccessRedirectsToTargetPathForNewUser(): void
    {
        $email = 'target@example.com';
        $gitHubApi = $this->createMock(GitHubApi::class);
        $gitHubApi->method('primaryEmail')->willReturn($email);

        $authenticator = new GitHubAuthenticator(
            $this->createClientRegistry('github'),
            $gitHubApi,
            $this->createRouter(),
            $this->createUserProvider($email, false, true),
            $this->createConfig('login_only', 'enabled'),
            $this->expectCreateUserDispatch($email)
        );

        $session = new Session(new MockArraySessionStorage());
        $session->set('_security.main.target_path', 'http://localhost/user');
        $request = $this->createRequest('login_github_check', $session);
        $authenticator->authenticate($request);

        $response = $authenticator->onAuthenticationSuccess($request, $this->createMock(TokenInterface::class), 'main');
        self::assertSame('http://localhost/user', $response->headers->get('location'));
        self::assertSame(['Your account has been created.'], $session->getFlashBag()->get('success'));
    }

    public function testUserGuardHelperRejectsDisabledUser(): void
    {
        $email = 'disabled@example.com';
        $helper = new UserGuardHelper(
            $this->createUserProvider($email, true, true, 'disabled'),
            $this->createMock(LoginFormAuthenticator::class),
            new TokenStorage(),
            new UserChecker()
        );

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Account is disabled.');

        $helper->authenticateUser($email, $this->createRequest('register_github_check'));
    }

    private function createConfig(string $localAuth, string $oauthRegistration): Config
    {
        $query = $this->createMock(ConfigQuery::class);
        $query->method('findAll')->willReturn([
            'local_authentication' => $localAuth,
            'oauth_registration' => $oauthRegistration,
        ]);

        return new Config($query, new ArrayAdapter());
    }

    private function createUserProvider(string $email, bool $existsBeforeCreate, bool $existsAfterCreate, string $status = 'enabled'): UserProvider
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('fetchOne')->willReturn($existsBeforeCreate ? 'user-id-1' : false);
        $connection->method('fetchAssociative')->willReturn($existsAfterCreate ? [
            'id' => 'user-id-1',
            'email' => $email,
            'password' => 'hashed',
            'status' => $status,
            'email_confirmed_at' => '2024-01-01 00:00:00',
            'email_confirm_token' => 'confirm-token',
            'roles' => '["ROLE_USER","ROLE_OAUTH_USER"]',
            'email_scan_result' => true,
            'timezone' => 'UTC',
        ] : false);
        $connection->method('fetchAllAssociative')->willReturn([]);

        return new UserProvider($connection, $this->createMock(UserRepository::class));
    }

    private function expectCreateUserDispatch(string $email): MessageBusInterface
    {
        $bus = $this->createMock(MessageBusInterface::class);
        $bus->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (object $message) use ($email): bool {
                return $message instanceof CreateOAuthUser && $message->email() === $email;
            }))
            ->willReturnCallback(static fn (object $message): Envelope => new Envelope($message));

        return $bus;
    }

    private function createClientRegistry(string $clientName): ClientRegistry
    {
        $client = $this->createMock(OAuth2ClientInterface::class);
        $client->method('getAccessToken')->willReturn(new AccessToken(['access_token' => 'secret']));

        $registry = $this->createMock(ClientRegistry::class);
        $registry->method('getClient')->with($clientName)->willReturn($client);

        return $registry;
    }

    private function createRouter(): RouterInterface
    {
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(static function (string $route, array $params = []): string {
            $query = $params !== [] ? '?'.http_build_query($params) : '';

            return '/'.$route.$query;
        });

        return $router;
    }

    private function createRequest(string $route, ?Session $session = null): Request
    {
        $request = new Request();
        $request->setSession($session ?? new Session(new MockArraySessionStorage()));
        $request->attributes->set('_route', $route);

        return $request;
    }
}
