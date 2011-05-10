<?php

/**
 * Google.class.php
 *
 * Extension of the OAuthClientBase to connect with Google
 *
 * @package OAuthClient
 */
class Google extends OAuthClientBase
{
  /*
   * Parameters required by OAuthClientBase class 
   */
  //protected $_consumerKey; load from oauth.yml
  //protected $_consumerSecret; load from oauth.yml
  protected $_apiBaseUri = 'http://api.twitter.com/1/';
  
  protected $_requestTokenUri = 'https://www.google.com/accounts/OAuthGetRequestToken';
  protected $_accessTokenUri = 'https://www.google.com/accounts/OAuthGetAccessToken';
  protected $_authorizeUri = 'https://www.google.com/accounts/OAuthAuthorizeToken';
  
  protected $_signatureMethods = array(
    'HMAC-SHA1'
  );
  
  //protected $_verificationCodeArgument = 'oauth_verifier';
  
  /*
   * Google specific parameters
   */
  protected $_scope;

  protected function _getCallbackUri ()
  {
    $ret = parent::_getCallbackUri();
    
    if ($_GET['next']) {
      $qspos = strpos($ret, '?');
      
      if ($qspos) {
        $qs = substr($ret, $qspos + 1);
        
        $qsar = parse_str($qs);
        
        unset($qsar['next']);
        
        $qs = http_build_query($qsar);
        
        $ret = substr($ret, 0, $qspos);
        
        if ($qs)
          $ret .= '?' . $qs;
      }
    }
    
    return $ret;
  }

  public function _getAccessToken ($method = 'POST', $options = array(), $curl_options = array())
  {
    $options['oauth_verifier'] = $_GET['oauth_verifier'];
    
    parent::_getAccessToken($method, $options, $curloptions);
  }

  public function _getRequestToken ($params = array(), $method = null)
  {
    if (! $params['scope']) {
      $params['scope'] = $this->_scope;
    }
    if (! $params['oauth_callback']) {
      $params['oauth_callback'] = $this->_getCallbackUri();
    }
    
    return parent::_getRequestToken($params, $method);
  }

  public function getAccessTokenUri ()
  {
    $ret = parent::getAccessTokenUri();
    
    $ret .= (strpos($ret, '?') === false) ? '?' : '&';
    
    $ret .= 'oauth_verifier=' . $_GET['oauth_verifier'];
    
    return $ret;
  }

  public function getAuthorizeUri ($data)
  {
    /*
     * set authorization parameters
     */
    if (! isset($data['oauth_token'])) {
      $data['oauth_token'] = $this->_requestToken['token'];
    }
    
    $ret = parent::getAuthorizeUri($data, false);
    
    return $ret;
  }

}
?>