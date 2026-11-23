<?php

declare(strict_types=1);

namespace Buddy\Repman\Security;

use Buddy\Repman\Service\Config;
use Buddy\Repman\Service\Integration\GitHubApi;
use Github\Exception\ExceptionInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;

final class GitHubAuthenticator extends OAuthAuthenticator
{
    private GitHubApi $gitHubApi;

    public function __construct(
        ClientRegistry $clientRegistry,
        GitHubApi $gitHubApi,
        RouterInterface $router,
        UserProvider $userProvider,
        Config $config,
        MessageBusInterface $messageBus
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->gitHubApi = $gitHubApi;
        $this->userProvider = $userProvider;
        $this->router = $router;
        $this->config = $config;
        $this->messageBus = $messageBus;
    }

    public function supports(Request $request): bool
    {
        return $request->attributes->get('_route') === 'login_github_check';
    }

    public function authenticate(Request $request): PassportInterface
    {
        $accessToken = $this->fetchAccessToken(
            $this->clientRegistry->getClient('github'),
            $request->attributes->get('_route')
        );

        try {
            $email = $this->gitHubApi->primaryEmail($accessToken->getToken());
        } catch (ExceptionInterface|\RuntimeException $exception) {
            throw new CustomUserMessageAuthenticationException($exception->getMessage());
        }

        return $this->createPassport($email, $request);
    }

    protected function providerName(): string
    {
        return 'github';
    }
}
