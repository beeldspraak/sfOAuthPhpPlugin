<?php

/**
 * MySpace.class.php
 *
 * Extension of the OAuthClientBase to connect with MySpace
 *
 * @package OAuthClient
 */
class MySpace extends OAuthClientBase
{
  /*
   * Parameters required by OAuthClientBase class 
   */
  //protected $_consumerKey; load from oauth.yml
  //protected $_consumerSecret; load from oauth.yml
  protected $_apiBaseUri = 'http://api.myspace.com/v1/';
  
  protected $_requestTokenUri = 'http://api.myspace.com/request_token';
  protected $_accessTokenUri = 'http://api.myspace.com/access_token';
  protected $_authorizeUri = 'http://api.myspace.com/authorize';

}
?>