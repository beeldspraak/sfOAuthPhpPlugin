<?php

/**
 * Facebook.class.php
 *
 * Extension of the OAuthClientBase to connect with Facebook
 *
 * @package OAuthClient
 */
class Facebook extends OAuthClientBase
{
  /*
   * Parameters required by OAuthClientBase class 
   */
  //protected $_consumerKey; load from oauth.yml
  //protected $_consumerSecret; load from oauth.yml	
  protected $_apiBaseUri = 'https://graph.facebook.com/';
  protected $_requestTokenUri = '';
  protected $_accessTokenUri = 'https://graph.facebook.com/oauth/access_token';
  protected $_authorizeUri = 'https://graph.facebook.com/oauth/authorize';
  protected $_signatureMethods = array(
    'PLAINTEXT'
  );
  protected $_verificationCodeArgument = 'code';
  
  /*
   * Facebook specific parameters
   */
  //protected $_applicationId; load from oauth.yml
  protected $_scope = "user_photos,user_videos,publish_stream";

  /*
   * Facebook doesn't use a request token so we need to do the swap ourselves
   */
  protected function _getAccessToken ($method = 'POST', $options = array(), $curl_options = array(), $autoDecodeVerificationCode = true)
  {
    if (! is_array($curl_options)) {
      $curl_options = array(
        $curl_options
      );
    }
    //if (!$curl_options['CURLOPT_POSTFIELDS']) $curl_options['CURLOPT_POSTFIELDS'] = 'client_id='.$this->_applicationId.'&redirect_uri='.rawurlencode($this->_callbackUri()).'&client_secret='.$this->_consumerSecret.'&code='.$_GET[$verificationCodeArgument];
    $uri = $this->accessTokenUri();
    $ch = curl_init($uri);
    $curl_options[CURLOPT_RETURNTRANSFER] = true;
    $curl_options[CURLOPT_CUSTOMREQUEST] = $method;
    curl_setopt_array($ch, $curl_options);
    //curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if (empty($body)) {
      throw new OAuthException2('No answer from the server "' . $uri . '" while requesting an access token');
    }
    if ($status != 200) {
      throw new OAuthException2('Unexpected result from the server "' . $uri . '" (' . $status . ') while requesting an access token');
    }
    parse_str($body, $data);
    if (! empty($data['access_token'])) {
      $this->_dataStore->addServerToken($this->_consumerKey, 'access', $data['access_token'], '---', $this->_userId, $options);
      $this->_checkForAccessToken();
    } else {
      throw new OAuthException2('The server "' . $uri . '" did not return the access token');
    }
  }

  public function getAccessTokenUri ()
  {
    $ret = parent::getAccessTokenUri();
    $ret .= (strpos($ret, '?') === false) ? '?' : '&';
    $ret .= 'client_id=' . $this->_applicationId . '&redirect_uri=' . rawurlencode($this->_getCallbackUri()) . '&client_secret=' . $this->_consumerSecret;
    if ($this->_getWebRequestParameter($this->_verificationCodeArgument)) {
      $ret .= '&code=' . $this->_getWebRequestParameter($this->_verificationCodeArgument);
    }
    return $ret;
  }

  protected function _getCallbackUri ()
  {
    $ret = parent::_getCallbackUri();
    //        if ($this->_getWebRequestParameter($this->_verificationCodeArgument) == false) {
    //          throw new OAuthException2('Get parameter not found for callbackUri: '.$this->_verificationCodeArgument);
    //        }
    if ($this->_getWebRequestParameter($this->_verificationCodeArgument)) {
      $qspos = strpos($ret, '?');
      if ($qspos) {
        $qs = substr($ret, $qspos + 1);
        $qsar = parse_str($qs);
        unset($qsar[$this->_verificationCodeArgument]);
        $qs = http_build_query($qsar);
        $ret = substr($ret, 0, $qspos);
        if ($qs)
          $ret .= '?' . $qs;
      }
    }
    
    return $ret;
  }

  protected function _getRequestToken ($params = array(), $method = 'POST', $options = array(), $curl_options = array())
  {
    return array();
  }

  public function getAuthorizeUri ($data = array(), $autoPopulateDefaults = true)
  {
    /*
     * set authorization parameters
     */
    $data['client_id'] = $this->_applicationId;
    $data['scope'] = $this->_scope;
    if (! $data['redirect_uri']) {
      $data['redirect_uri'] = $this->_getCallbackUri();
    }
    $ret = parent::getAuthorizeUri($data, false);
    
    return $ret;
  }

  public function doRequest ($uri, $parameters = array(), $method = 'GET', $files = array(), $curl_options = array(), $options = array())
  {
    if ($this->_checkForAccessToken() || ($this->_getWebRequestParameter($this->_verificationCodeArgument) && $this->_connectionAttempt == 0)) {
      
      /**
       * Check whether an access token is provided in the querystring
       */
      if ($this->_getWebRequestParameter($this->_verificationCodeArgument)) {
        //if so register it with oauth-php
        $this->_getAccessToken();
        $this->_connectionAttempt ++;
      
   //$this->_dataStore->addServerToken($this->_consumerKey, 'access', $requestParams['oauth_token'], $requestParams['oauth_secret']);
      }
      $uri .= (strpos($uri, '?') === false) ? '?' : '&';
      $uri .= 'access_token=' . $this->_accessToken['token'];
    }
    
    return parent::doRequest($uri, $parameters, $method, $files, $curl_options, $options);
  }
}
?>