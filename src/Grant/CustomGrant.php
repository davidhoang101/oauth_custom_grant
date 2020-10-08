<?php

namespace Drupal\oauth_custom_grant\Grant;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Grant\AbstractGrant;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Password grant class.
 */
class CustomGrant extends AbstractGrant
{
    /**
     * @param UserRepositoryInterface         $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
      UserRepositoryInterface $userRepository,
      RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
      $this->setUserRepository($userRepository);
      $this->setRefreshTokenRepository($refreshTokenRepository);

      $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
      ServerRequestInterface $request,
      ResponseTypeInterface $responseType,
      \DateInterval $accessTokenTTL
    ) {
        // Validate request
      $client = $this->validateClient($request);
      $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
      $user = $this->validateUser($request, $client);

      // Finalize the requested scopes
      $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

      // Issue and persist new tokens
      $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
      $refreshToken = $this->issueRefreshToken($accessToken);

      // Inject tokens into response
      $responseType->setAccessToken($accessToken);
      $responseType->setRefreshToken($refreshToken);

      return $responseType;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ClientEntityInterface  $client
     *
     * @throws OAuthServerException
     *
     * @return UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client){   
      $email = $this->getRequestParameter('email', $request);
      if (is_null($email)) {
        throw OAuthServerException::invalidRequest('email');
      }

      $custom_token = $this->getRequestParameter('custom_token', $request);
      if (is_null($custom_token)) {
        throw OAuthServerException::invalidRequest('custom_token');
      }

      $user = $this->userRepository->getUserEntityByUserCredentials(
        $custom_token,
        $email,
        $this->getIdentifier(),
        $client
      );
      if ($user instanceof UserEntityInterface === false) {
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

        throw OAuthServerException::invalidCredentials();
      }

      return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
      return 'custom';
    }
  }
