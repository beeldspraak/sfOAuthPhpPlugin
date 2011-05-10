<?php

/**
 * SoundCloud.class.php
 *
 * Extension of the OAuthClientBase class to connect with SoundCloud.com
 * 
 * @package  OAuthClient
 */
class SoundCloud extends OAuthClientBase
{
  /*
     * Parameters required by OAuthClientBase class 
     */
  //protected $_consumerKey; load from oauth.yml
  //protected $_consumerSecret; load from oauth.yml
  protected $_apiBaseUri = 'http://api.soundcloud.com/';
  
  protected $_requestTokenUri = 'http://api.soundcloud.com/oauth/request_token';
  protected $_accessTokenUri = 'http://api.soundcloud.com/oauth/access_token';
  protected $_authorizeUri = 'http://soundcloud.com/oauth/authorize';

}
?>