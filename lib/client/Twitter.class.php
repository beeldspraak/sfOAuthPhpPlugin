<?php

/**
 * Twitter.class.php
 *
 * Extension of the OAuthClientBase class to connect with Twitter
 * 
 * @package OAuthClient
 */
class Twitter extends OAuthClientBase
{
  /*
   * Parameters required by OAuthClientBase class 
   */
  //protected $_consumerKey; load from oauth.yml
  //protected $_consumerSecret; load from oauth.yml	
  protected $_apiBaseUri = 'http://api.twitter.com/1/';
  
  protected $_requestTokenUri = 'https://twitter.com/oauth/request_token';
  protected $_accessTokenUri = 'https://twitter.com/oauth/access_token';
  protected $_authorizeUri = 'https://twitter.com/oauth/authorize';

  /*
   * Twitter specific parameters
   */
  //protected $_callbackUri; load from oauth.yml
  

  public function _getRequestToken ($params = array(), $method = 'POST', $options = array(), $curl_options = array())
  {
    // add callback when requesting token
    if (! isset($params['oauth_callback'])) {
      $params['oauth_callback'] = $this->_getCallbackUri();
    }
    
    return parent::_getRequestToken($params, $method, $options, $curl_options);
  }

  public function _getAccessToken ($method = 'POST', $options = array(), $curl_options = array(), $autoDecodeVerificationCode = true)
  {
    if (! isset($options['oauth_verifier']) && $this->_getWebRequestParameter('oauth_verifier')) {
      $options['oauth_verifier'] = $this->_getWebRequestParameter('oauth_verifier');
    }
    
    parent::_getAccessToken($method, $options, $curl_options, $autoDecodeVerificationCode);
  }
}
?>