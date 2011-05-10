<?php

/**
 * OAuthClientBase.class.php
 *
 * Base class to connect webservice servers that authenticate with OAuth
 *
 * @package OAuthClient
 */
class OAuthClientBase
{
  
  /**
   * These store our Consumer Key and Consumer Secret that we were given 
   * when we registered our application with the webservice.
   * 
   * @var string 
   */
  protected $_consumerKey;
  protected $_consumerSecret;
  
  /**
   * These are the different URIs that are used in the authorization process. 
   * They will also be given to you once you have registered.
   * 
   * @var string
   */
  protected $_requestTokenUri;
  protected $_authorizeUri;
  protected $_accessTokenUri;
  
  /**
   * An array of the dif- ferent signing methods supported by the provider.
   * 
   * @var array
   */
  protected $_signatureMethods = array(
    'HMAC-SHA1', 'PLAINTEXT'
  );
  
  /**
   * Typically API request URIs all have the same prefix, so we store this here. 
   * Examples are https://graph.facebook.com and http://api.myspace.com/v1/.
   * 
   * @var string
   */
  protected $_apiBaseUri;
  
  /**
   * A callback from the API should be directed back to this URI, if not set
   * the request URI is taken
   * 
   * @var string
   */
  protected $_callbackUri;
  
  /**
   * The type of data store we want to use to keep our tokens. This must be one 
   * of the store types supported by oauth-php.
   * 
   * @var string
   */
  //protected $_dataStoreType = 'PDO';
  

  /**
   * Configuration options for our data store. If you are using MySQL, 
   * these are the login details for your MySQL database.
   * 
   * @var array
   */
  //  protected $_dataStoreOptions = array(
  //    'server'    => '<YOUR DB SERVER HERE>', 
  //    'username'  => '<YOUR DB USER HERE>', 
  //    'password'  => '<YOUR DB PASSWORD HERE>', 
  //    'database'  => '<YOUR DB NAME HERE>',
  //  );
  

  /**
   * One of the small but critical differences between providers is the name of 
   * the query string parameter that contains the signed Request Token. By 
   * keeping this as a configuration variable, we can easily adapt our class to 
   * deal with this difference.
   * 
   * @var string
   */
  protected $_verificationCodeArgument = 'oauth_token';
  
  /**
   * Cache the tokens
   * 
   * @var string
   */
  protected $_tokenName;
  protected $_accessToken;
  protected $_requestToken;
  
  /**
   * Amount of connection attemps
   * 
   * @var integer
   */
  protected $_connectionAttempt = 0;
  
  /**
   * OAuth storage instance
   * 
   * @var OAuthStoreSQL
   */
  protected $_dataStore;
  
  /**
   * Id of the user to connect to the provider
   * 
   * @var int
   */
  protected $_userId;
  
  /**
   * Array containing get parameters
   * 
   * @var array
   */
  protected $_requestParameters;

  /**
   * Constructor function for the OAuthClientBase class
   * 
   * @param integer $userId Id of the user to connect to the provider as
   * @param PDO $conn
   * @param array $requestParameters optionally provide an array of (validated) GET parameters, 
   * fe. if these can be retreived from a framework, by default $_GET is used
   */
  public function __construct ($userId = null, $requestParameters = array(), PDO $conn = null)
  {
    // user id
    $this->_userId = $userId;
    
    // load yaml config
    $this->loadYamlConfig();
    
    // request parameters
    if (count($requestParameters) == 0 && count($_GET) > 0) {
      $requestParameters = $_GET;
    }
    $this->_requestParameters = $requestParameters;
    
    // data store
    if (is_null($conn)) {
      $conn = Doctrine_Manager::connection()->getDbh();
    }
    
    $this->_dataStore = OAuthStore::instance('PDO', array(
      'conn' => $conn
    ));
    
    // enable logging
    if (! defined('OAUTH_LOG_REQUEST')) {
      define('OAUTH_LOG_REQUEST', true);
    }
    
    // set the name of the token to the client class
    $this->_tokenName = strtolower(get_class($this));
    
    /** 
     * Check to see whether this provider is already registered with OAuth
     * If not register it 
     */
    try {
      $server = $this->_dataStore->getServer($this->_consumerKey, $this->_userId);
    } catch (OAuthException2 $e) {
      $server = array(
        'consumer_key' => $this->_consumerKey, 'consumer_secret' => $this->_consumerSecret, 'server_uri' => $this->_apiBaseUri, 
      'signature_methods' => $this->_signatureMethods, 'request_token_uri' => $this->getRequestTokenUri(), 'authorize_uri' => $this->_authorizeUri, 
      'access_token_uri' => $this->getAccessTokenUri()
      );
      
      // Save the server in the the OAuthStore
      $consumer_key = $this->_dataStore->updateServer($server, $this->_userId);
    }
  }

  protected function loadYamlConfig ()
  {
    $client = strtolower(get_class($this));
    $oauth_config = include sfContext::getInstance()->getConfigCache()->checkConfig('config/oauth.yml');
    $config = isset($oauth_config['clients'][$client]) ? $oauth_config['clients'][$client] : array();
    
    foreach ($config as $name => $parameter) {
      $name = '_' . $name;
      $this->$name = $parameter;
    }
  }

  /**
   * Get a parameter from the webrequest
   * 
   * @param string $name
   * @param mixed $default
   * @return mixed 
   */
  protected function _getWebRequestParameter ($name, $default = false)
  {
    return isset($this->_requestParameters[$name]) ? $this->_requestParameters[$name] : $default;
  }

  /**
   * Returns the uri to swap a request token for an access token
   * 
   * @return string
   */
  public function getAccessTokenUri ()
  {
    return $this->_accessTokenUri;
  }

  /**
   * Returns the uri to redirect a user to authorize a request token
   * 
   * @param array $data Key-Value pairs of data to pass in the querystring when generating the authorization uri.
   * @param boolean $autoPopulateDefault If true the oauth_token and oauth_callback properties are automatically set 
   * @return string
   */
  public function getAuthorizeUri ($data = array(), $autoPopulateDefaults = true)
  {
    $authorizeUri = false;
    
    /* 
     * Check whether to automatically add in defaults 
     */
    if ($autoPopulateDefaults) {
      if (! isset($data['oauth_token'])) {
        $data['oauth_token'] = $this->_requestToken['token'];
      }
      if (! isset($data['oauth_callback'])) {
        $data['oauth_callback'] = $this->_getCallbackUri();
      }
      
      //if (!$data['oauth_token']) throw new Exception('Cannot authorize without a request token');
      

      $authorizeUri = $this->_requestToken['authorize_uri'];
    }
    
    /*
     * Build the url
     */
    if (! $authorizeUri) {
      $authorizeUri = $this->_authorizeUri;
    }
    
    $authorizeUri .= (strpos($authorizeUri, '?') === false) ? '?' : '&';
    
    foreach ($data as $dkey => $dval) {
      if ($dval)
        $authorizeUri .= $dkey . '=' . rawurlencode($dval) . "&";
    }
    
    $authorizeUri = substr($authorizeUri, 0, - 1);
    
    return $authorizeUri;
  }

  /**
   * Returns the uri to get a request token
   * 
   * @return string
   */
  public function getRequestTokenUri ()
  {
    return $this->_requestTokenUri;
  }

  /**
   * Returns the default callback uri based on the original page request
   * 
   * @return string
   */
  protected function _getCallbackUri ()
  {
    //    if ($this->_callbackUri)
    //      return $this->_callbackUri;
    

    $ret = '';
    $protocol = '';
    
    switch ($_SERVER['SERVER_PORT']) {
      case '443':
        $protocol = 'https';
        break;
      case '80':
      default:
        $protocol = 'http';
        break;
    }
    
    $ret = $protocol . '://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
    
    return $ret;
  }

  /**
   * Checks whether an access token exists for this user and provider
   * 
   * @return boolean
   */
  protected function _checkForAccessToken ()
  {
    $ret = false;
    
    if ($this->_accessToken) {
      $ret = true;
    } else {
      try {
        $this->_accessToken = $this->_dataStore->getSecretsForSignature($this->_apiBaseUri, $this->_userId, $this->_tokenName);
        
        $ret = true;
      } catch (OAuthException2 $e) {
        // no access token in storage
      }
    }
    
    return $ret;
  }

  /**
   * Gets a new request token via a call to OAuthRequester::requestRequestToken()
   * The results are cached in $this->_requestTokenParams
   * 
   * @param array $params custom parameters when requesting the token
   * @param string $method HTTP method to use
   * @param array $options Array of options to pass to oauth-php
   * @param array $curl_options Array of curl options to pass to oauth-php
   * @return array The results of the call 
   */
  protected function _getRequestToken ($params = array(), $method = 'POST', $options = array(), $curl_options = array())
  {
    $options['name'] = $this->_tokenName;
    
    $this->_requestToken = OAuthRequester::requestRequestToken($this->_consumerKey, $this->_userId, $params, $method, $options, $curl_options);
    
    return $this->_requestToken;
  }

  /**
   * Requests the user to authorize the request token by redirecting to a
   * login page on the providers website
   * If page headers have already been sent, the request will be done via
   * javascript. Otherwise a Location header is sent
   * 
   * @param array $data Data to pass to the authorizeUri() method when generating the uri
   */
  protected function _authorize ($data = array())
  {
    if (headers_sent()) {
      // fallback to javascript
      echo '<script type="text/javascript">window.location = "' . $this->getAuthorizeUri($data) . '";</script>';
      die();
    } else {
      // redirect to autorize uri
      header('Location: ' . $this->getAuthorizeUri($data));
      die();
    }
  }

  /**
   * Exchanges a signed request token for an access token
   * 
   * @param string $method HTTP method to use
   * @param array $options Array of options to pass to oauth-php
   * @param array $curl_options Array of curl options to pass to oauth-php
   * @param boolean $autoDecodeVerificationCode Whether to automatically decode the signed request token
   */
  protected function _getAccessToken ($method = 'POST', $options = array(), $curl_options = array(), $autoDecodeVerificationCode = true)
  {
    if ($this->_getWebRequestParameter($this->_verificationCodeArgument) == false) {
      throw new OAuthException2('Get parameter not found for accesstoken: ' . $this->_verificationCodeArgument);
    }
    
    $verificationCode = $this->_getWebRequestParameter($this->_verificationCodeArgument);
    
    if ($autoDecodeVerificationCode) {
      $verificationCode = rawurldecode($verificationCode);
    }
    
    OAuthRequester::requestAccessToken($this->_consumerKey, $verificationCode, $this->_userId, $method, $options, $curl_options);
  }

  /**
   * Delete token and consumer registry
   * 
   * @return void
   */
  public function unconnect ()
  {
    $this->_dataStore->deleteServer($this->_consumerKey, $this->_userId);
  }

  /**
   * Return if there is an access token
   * 
   * @return boolean 
   */
  public function isConnected ()
  {
    return $this->_checkForAccessToken();
  }

  /**
   * Performs an HTTP request on the specified URL
   * 
   * @param string $uri the URL to request
   * @param array $parameters name=>value array with request parameters
   * @param string $method The HTTP method to use for the request
   * @param array $files the supplied file (or data) is encoded as the request body and add a content-disposition header.
   * @param array $curl_options Array of curl options to pass to oauth-php
   * @param array $options Array of options to pass to oauth-php
   * @return array (code=>int, headers=>array(), body=>string) An array of the response data
   */
  public function doRequest ($uri, $parameters = array(), $method = 'GET', $files = array(), $curl_options = array(), $options = array())
  {
    if (! $this->_checkForAccessToken()) {
      /*
       *  Check whether a verified token is provided in the querystring
       */
      if ($this->_getWebRequestParameter($this->_verificationCodeArgument)) {
        //if so swap if for an access token
        $this->_getAccessToken();
      } else {
        //otherwise get a request token and authorize it
        $this->_getRequestToken();
        $this->_authorize();
      }
    }
    
    // prepend baseUri if needed
    if ((substr($uri, 0, 7) != 'http://') && (substr($uri, 0, 8) != 'https://')) {
      $uri = $this->_apiBaseUri . $uri;
    }
    
    // add the token name
    $options['name'] = $this->_tokenName;
    
    // At the moment OAuth does not support multipart/form-data, so try to encode
    // the supplied file (or data) as the request body and add a content-disposition header.
    $request = new OAuthRequester($uri, $method, $parameters, null, $files);
    
    try {
      $result = $request->doRequest($this->_userId, $curl_options, $options);
    } catch (OAuthException2 $e) {
      // most common is that the user has revoked access for our application 
      // with the provider or that our Access Token has expired
      if ($this->_connectionAttempt == 0) {
        $this->_dataStore->deleteServerToken($this->_consumerKey, $this->_accessToken['token'], 0, true);
        
        unset($this->_accessToken);
        
        $this->_connectionAttempt ++;
        
        // 2nd attempt, if this also fails an OAuthException2 is thrown
        $result = $this->doRequest($uri, $parameters, $method, $files, $curl_options, $options);
      } else {
        throw $e;
      }
    }
    
    return $result;
  }

  /**
   * Performs an HTTP DELETE request on the specified url
   * 
   * @param string the URI to request
   * @param array $parameters name=>value array with request parameters
   * @return array (code=>int, headers=>array(), body=>string) An array of the response data
   */
  public function delete ($uri, $parameters = array())
  {
    return $this->doRequest($uri, $parameters, 'DELETE');
  }

  /**
   * Performs an HTTP GET request on the specified url
   * 
   * @param string the URI to request
   * @param array $parameters name=>value array with request parameters
   * @return array (code=>int, headers=>array(), body=>string) An array of the response data
   */
  public function get ($uri, $parameters = array())
  {
    return $this->doRequest($uri, $parameters, 'GET');
  }

  /**
   * Performs an HTTP POST request on the specified url
   * 
   * @param string the URI to request
   * @param array $parameters name=>value array with request parameters
   * @return array (code=>int, headers=>array(), body=>string) An array of the response data
   */
  public function post ($uri, $parameters = array())
  {
    return $this->doRequest($uri, $parameters, 'POST');
  }

  /**
   * Performs an HTTP PUT request on the specified url
   * 
   * @param string the URI to request
   * @param array $parameters name=>value array with request parameters
   * @return array (code=>int, headers=>array(), body=>string) An array of the response data
   */
  public function put ($uri, $parameters = array())
  {
    return $this->doRequest($uri, $parameters, 'PUT');
  }
}
?>
