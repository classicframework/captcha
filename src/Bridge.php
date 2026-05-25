<?php

namespace classicframework\captcha;

use classicframework\core\App;
use classicframework\core\Config;
use classicframework\core\BridgeInterface;

class Bridge implements BridgeInterface
{
  public static function register(App $app)
  {
    $config = Config::extract('captcha');

    $session = $app->get_service('session');
    $captcha = new Captcha($config, $session);

    $app->set_service('captcha', $captcha);
  }
}