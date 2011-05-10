<?php

/**
 * OAuthUser.class.php
 *
 * Base class to connect webservice providers that authenticate with OAuth
 *
 * @package sfOAuthPhpPlugin
 */
class OAuthUser
{
  /**
   * Collection of OAuthClient objects
   * 
   * @var array
   */
  protected static $OAuthClients = null;

  /**
   * Event listener to connect this class to the user class
   * 
   * @param sfEvent $event
   */
  static public function methodNotFound(sfEvent $event)
  {
    if ( method_exists('OAuthUser', $event['method']) ) {
      $event->setReturnValue(call_user_func_array(array(
        'OAuthUser', 
        $event['method']
      ), array_merge(array(
        $event->getSubject()
      ), $event['arguments'])));
      
      return true;
    }
  }

  /**
   * Get a client to communicate with the server of the specified client
   * 
   * @param sfUser $user
   * @param string $client_name
   * @param array $requestParameters optionally provide an array of (validated) GET parameters
   * @return OAuthClientBase 
   */
  static public function getOAuthClient(sfUser $user, $client_name, $requestParameters = array())
  {
    if ( !isset(self::$OAuthClients[$client_name]) ) {
      $class = sfInflector::camelize($client_name);
      if ( !class_exists($class) ) {
        return false;
      }
      
      if ( method_exists($user, 'isOAuthPublic') && $user->isOAuthPublic() ) {
        $userId = null;
      } elseif ( method_exists($user, 'getGuardUser') ) {
        $userId = $user->getGuardUser()->getId();
      } else {
        $userId = null;
      }
      
      self::$OAuthClients[$client_name] = new $class($userId, $requestParameters);
    }
    
    return self::$OAuthClients[$client_name];
  }

  /**
   * Return the connected clients
   * 
   * @param sfUser $user
   * @param array $client_names	clients to check
   * @return array	connected client names
   */
  static public function getConnectedOAuthClients(sfUser $user, array $client_names = array())
  {
    $connected = array();
    
    if ( count($client_names) ) {
      foreach ($client_names as $client_name) {
        $client = self::getOAuthClient($user, $client_name);
        if ( $client && $client->isConnected() ) {
          $connected[] = $client_name;
        }
      }
    } else {
      foreach (self::getAvailableOAuthClients($user) as $name => $client) {
        if ( $client && $client->isConnected() ) {
          $connected[] = $name;
        }
      }
    }
    
    return $connected;
  }

  /**
   * Return if the user has an access token for the specified client
   * 
   * @param sfUser $user
   * @param type $client_name
   * @return boolean 
   */
  static public function isOAuthConnected(sfUser $user, $client_name)
  {
    $client = self::getOAuthClient($user, $client_name);
    
    return $client !== false ? $client->isConnected() : false;
  }

  /**
   * Return the unconnected clients
   * 
   * @param sfUser $user
   * @param array $client_names	clients to check
   * @return array	unconnected client names
   */
  static public function getUnConnectedOAuthClients(sfUser $user, array $client_names = array())
  {
    $unConnected = array();
    
    if ( count($client_names) ) {
      foreach ($client_names as $client_name) {
        $client = self::getOAuthClient($user, $client_name);
        if ( $client && $client->isConnected() == false ) {
          $unConnected[] = $client_name;
        }
      }
    } else {
      foreach (self::getAvailableOAuthClients($user) as $name => $client) {
        if ( $client && $client->isConnected() == false ) {
          $unConnected[] = $name;
        }
      }
    }
    
    return $unConnected;
  }

  /**
   * Return the available clients, this are the clients listed in oauth.yml
   * 
   * @param sfUser $user
   * @param array $client_names	clients to check
   * @return array	available client names
   */
  static public function getAvailableOAuthClients(sfUser $user)
  {
    if ( is_null(self::$OAuthClients) ) {
      self::$OAuthClients = array();
      $config = include sfContext::getInstance()->getConfigCache()->checkConfig('config/oauth.yml');
      if ( isset($config['clients']) && is_array($config['clients']) ) {
        foreach (array_keys($config['clients']) as $client_name) {
          self::getOAuthClient($user, $client_name);
        }
      }
    }
    
    return self::$OAuthClients;
  }
}

?>
