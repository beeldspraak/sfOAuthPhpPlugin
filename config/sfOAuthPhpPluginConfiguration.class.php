<?php

/**
 * sfOAuthPhpPlugin configuration.
 * 
 * @package     sfOAuthPhpPlugin
 * @subpackage  config
 */
class sfOAuthPhpPluginConfiguration extends sfPluginConfiguration
{
  const VERSION = '1.0.0-DEV';

  /**
   * @see sfPluginConfiguration
   */
  public function initialize()
  {
    $this->dispatcher->connect('user.method_not_found', array(
      'OAuthUser', 
      'methodNotFound'
    ));
  }
}
