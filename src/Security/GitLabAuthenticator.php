<?php

declare(strict_types=1);

namespace Buddy\Repman\Security;

use Buddy\Repman\Service\Config;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Exception\IdentityProviderAuthenticationException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Omines\OAuth2\Client\Provider\GitlabResourceOwner;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;

final class GitLabAuthenticator extends OAuthAuthenticator
{
    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        UserProvider $userProvider,
        Config $config,
        MessageBusInterface $messageBus
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->userProvider = $userProvider;
        $this->router = $router;
        $this->config = $config;
        $this->messageBus = $messageBus;
    }

    public function supports(Request $request): bool
    {
        return $request->attributes->get('_route') === 'login_gitlab_check';
    }

    public function authenticate(Request $request): PassportInterface
    {
        $client = $this->clientRegistry->getClient('gitlab');

        try {
            /** @var GitlabResourceOwner $gitLabUser */
            $gitLabUser = $client->fetchUserFromToken($this->fetchAccessToken(
                $client,
                $request->attributes->get('_route')
            ));
        } catch (IdentityProviderException|IdentityProviderAuthenticationException $exception) {
            throw new CustomUserMessageAuthenticationException($exception->getMessage());
        }

        $userData = $gitLabUser->toArray();
        $email = isset($userData['email']) && \is_string($userData['email']) ? $userData['email'] : '';

        return $this->createPassport($email, $request);
    }

    protected function providerName(): string
    {
        return 'gitlab';
    }
}
