<?php

/**
 * Hyves.class.php
 *
 * Extension of the OAuthClientBase class to connect with Hyves
 * 
 * @package OAuthClient
 */
class Hyves extends OAuthClientBase
{
  /*
   * Parameters required by OAuthClientBase class 
   */
  //protected $_consumerKey; load from oauth.yml
  //protected $_consumerSecret; load from oauth.yml
  protected $_apiBaseUri = 'http://data.hyves-api.nl/';
  
  protected $_requestTokenUri = 'http://data.hyves-api.nl';
  protected $_accessTokenUri = 'http://data.hyves-api.nl';
  protected $_authorizeUri = 'http://www.hyves.nl/api/authorize';
  
  /*
   * Hyves specific parameters
   */
  protected $_defaultUriOptions = array(
    'ha_version' => '2.0', 'ha_format' => 'xml', 'ha_fancylayout' => 'false'
  );
  protected $_methods = "users.getScraps,users.getLoggedin,wwws.getByUser,wwws.create";

  public function getRequestTokenUri ()
  {
    $ret = parent::getRequestTokenUri();
    
    $ret .= (strpos($ret, '?') === false) ? '?' : '&';
    
    $params = $this->_defaultUriOptions;
    $params['ha_method'] = 'auth.requesttoken';
    $params['strict_oauth_spec_response'] = 'true';
    
    $ret .= http_build_query($params);
    
    return $ret;
  }

  public function _getRequestToken ($params = array(), $method = 'POST', $options = array(), $curl_options = array())
  {
    if (! isset($params['methods'])) {
      $params['methods'] = $this->_methods;
    }
    if (! isset($params['expirationtype'])) {
      // default  --- Default token, valid for 6 hour.
      // infinite --- Infinite token, no expiration time
      // user     --- The User chooses the expiredate for the token.
      $params['expirationtype'] = 'infinite';
    }
    
    return parent::_getRequestToken($params, $method, $options, $curl_options);
  }

  public function getAccessTokenUri ()
  {
    $ret = parent::getAccessTokenUri();
    
    $ret .= (strpos($ret, '?') === false) ? '?' : '&';
    
    $params = $this->_defaultUriOptions;
    $params['ha_method'] = 'auth.accesstoken';
    $params['strict_oauth_spec_response'] = 'true';
    
    $ret .= http_build_query($params);
    
    return $ret;
  }

  public function doRequest ($uri, $parameters = array(), $method = 'GET', $files = array(), $curl_options = array(), $options = array())
  {
    $parameters = array_merge($parameters, $this->_defaultUriOptions);
    
    return parent::doRequest($uri, $parameters, $method, $files, $curl_options, $options);
  }
}
?>