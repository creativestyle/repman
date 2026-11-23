<?php

declare(strict_types=1);

namespace Buddy\Repman\Security;

use Buddy\Repman\Message\User\CreateOAuthUser;
use Buddy\Repman\Service\Config;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Exception\InvalidStateException;
use KnpU\OAuth2ClientBundle\Exception\MissingAuthorizationCodeException;
use KnpU\OAuth2ClientBundle\Security\Exception\IdentityProviderAuthenticationException;
use KnpU\OAuth2ClientBundle\Security\Exception\InvalidStateAuthenticationException;
use KnpU\OAuth2ClientBundle\Security\Exception\NoAuthCodeAuthenticationException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

abstract class OAuthAuthenticator extends AbstractAuthenticator
{
    use TargetPathTrait;

    private const USER_CREATED_ATTRIBUTE = '_oauth_user_created';

    protected ClientRegistry $clientRegistry;
    protected UserProvider $userProvider;
    protected RouterInterface $router;
    protected Config $config;
    protected MessageBusInterface $messageBus;

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        $session = $request->getSession();
        $isNewUser = $request->attributes->getBoolean(self::USER_CREATED_ATTRIBUTE);

        if (($targetPath = $this->getTargetPath($session, $firewallName)) !== null) {
            if ($isNewUser) {
                $this->addFlash($session, 'success', 'Your account has been created.');
            }

            return new RedirectResponse($targetPath);
        }

        if ($isNewUser) {
            if ($session->has('organization-token')) {
                $this->addFlash($session, 'success', 'Your account has been created.');

                return new RedirectResponse($this->router->generate('organization_accept_invitation', [
                    'token' => $session->remove('organization-token'),
                ]));
            }

            $this->addFlash($session, 'success', 'Your account has been created. Please create a new organization.');

            return new RedirectResponse($this->router->generate('organization_create', [
                'origin' => $this->providerName(),
            ]));
        }

        return new RedirectResponse($this->router->generate('index'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $this->addFlash(
            $request->getSession(),
            'danger',
            strtr($exception->getMessageKey(), $exception->getMessageData())
        );

        return new RedirectResponse($this->router->generate('app_login'));
    }

    abstract protected function providerName(): string;

    protected function createPassport(string $email, Request $request): SelfValidatingPassport
    {
        $email = trim($email);
        if ($email === '') {
            throw new CustomUserMessageAuthenticationException('Primary e-mail not found.');
        }

        if (!$this->userProvider->emailExist($email)) {
            if (!$this->config->oauthRegistrationEnabled()) {
                throw new UserNotFoundException();
            }

            $this->messageBus->dispatch(new CreateOAuthUser($email));
            $request->attributes->set(self::USER_CREATED_ATTRIBUTE, true);
        }

        $user = $this->userProvider->loadUserByIdentifier($email);

        return new SelfValidatingPassport(new UserBadge($email, static function () use ($user): UserInterface {
            return $user;
        }));
    }

    /**
     * @codeCoverageIgnore
     */
    protected function fetchAccessToken(OAuth2ClientInterface $client, string $route): AccessToken
    {
        try {
            return $client->getAccessToken([
                'redirect_uri' => $this->router->generate($route, [], UrlGeneratorInterface::ABSOLUTE_URL),
            ]);
        } catch (MissingAuthorizationCodeException $e) {
            throw new NoAuthCodeAuthenticationException();
        } catch (IdentityProviderException $e) {
            throw new IdentityProviderAuthenticationException($e);
        } catch (InvalidStateException $e) {
            throw new InvalidStateAuthenticationException($e);
        }
    }

    private function addFlash(SessionInterface $session, string $type, string $message): void
    {
        if ($session instanceof Session) {
            $session->getFlashBag()->add($type, $message);
        }
    }
}
