<?php

namespace Drupal\oauth_custom_grant\Repositories;

use Drupal\user\UserAuthInterface;
use Drupal\user\Entity\User;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Drupal\simple_oauth\Entities\UserEntity;
use GuzzleHttp\Exception\RequestException;

class UserRepository implements UserRepositoryInterface {

  /**
   * @var \Drupal\user\UserAuthInterface
   */
  protected $userAuth;

  /**
   * UserRepository constructor.
   *
   * @param \Drupal\user\UserAuthInterface $user_auth
   *   The service to check the user authentication.
   */
  public function __construct(UserAuthInterface $user_auth) {
    $this->userAuth = $user_auth;
  }

  /**
   * {@inheritdoc}
   */
  public function getUserEntityByUserCredentials($token, $email, $grantType, ClientEntityInterface $clientEntity) {
    $UserEntity = new UserEntity();
    $client = \Drupal::httpClient();

    try {
      //@todo validate token such as apple sign in token, google sign in token, facebook sign in token,..

      //Check if user exist.
      $user = user_load_by_mail($email);
      if ($user) {
        $user_id  = $user->id();
        $UserEntity->setIdentifier($user_id);

        return $UserEntity;
      }
      else {
        return null;
      }
    } 
    catch (RequestException $e) {
      return null;
    }  
  }

}
