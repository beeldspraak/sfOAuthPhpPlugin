<?php
/**
 * Youtube.class.php
 *
 * Extension of the OAuthClientBase class to connect with YouTube
 * 
 * @package OAuthClient
 */
class YouTube extends Google
{
  protected $_requestTokenUri = 'https://www.google.com/accounts/OAuthGetRequestToken';
  
  protected $_apiBaseUri = 'http://gdata.youtube.com/feeds/api/';
  
  protected $_scope = 'http://gdata.youtube.com/';
}
?>