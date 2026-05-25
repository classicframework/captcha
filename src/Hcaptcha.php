<?php

namespace classicframework\captcha;

class Hcaptcha
{
  protected $config = array();
  protected $counter = 0;

  public function __construct($config = array())
  {
    $this->config = is_array($config) ? $config : array();
  }

  public function head()
  {
    return '<script src="https://www.hCaptcha.com/1/api.js" async defer></script>' . "\n";
  }

  public function body($options = array())
  {
    $options = is_array($options) ? $options : array();

    $mode = isset($options['mode']) ? (string) $options['mode'] : 'visible';
    $sitekey = isset($options['sitekey']) ? (string) $options['sitekey'] : $this->sitekey();

    if ($mode === 'invisible') {
      return $this->invisible($sitekey, $options);
    }

    return $this->visible($sitekey);
  }

  public function verify($data = null, $remote_ip = null)
  {
    if ($data === null) {
      $data = $_POST;
    }

    if (!is_array($data)) {
      return false;
    }

    $secret = $this->secret();

    if ($secret === '') {
      return false;
    }

    $token = isset($data['h-captcha-response']) ? (string) $data['h-captcha-response'] : '';

    if ($token === '') {
      return false;
    }

    if ($remote_ip === null) {
      $remote_ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
    }

    $response = $this->request_verify($secret, $token, $remote_ip);

    if (!is_array($response)) {
      return false;
    }

    return isset($response['success']) && $response['success'] === true;
  }

  protected function request_verify($secret, $token, $remote_ip)
  {
    $post_data = http_build_query(array(
      'secret' => $secret,
      'response' => $token,
      'remoteip' => $remote_ip,
    ), '', '&');

    if (function_exists('curl_init')) {
      $ch = curl_init('https://hcaptcha.com/siteverify');

      curl_setopt($ch, CURLOPT_POST, true);
      curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_TIMEOUT, 10);

      $result = curl_exec($ch);
      curl_close($ch);

      if ($result === false || $result === '') {
        return false;
      }

      $decoded = json_decode($result, true);

      return is_array($decoded) ? $decoded : false;
    }

    $context = stream_context_create(array(
      'http' => array(
        'method' => 'POST',
        'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => $post_data,
        'timeout' => 10,
      ),
    ));

    $result = @file_get_contents('https://hcaptcha.com/siteverify', false, $context);

    if ($result === false || $result === '') {
      return false;
    }

    $decoded = json_decode($result, true);

    return is_array($decoded) ? $decoded : false;
  }

  protected function secret()
  {
    return isset($this->config['hcaptcha_secret']) ? (string) $this->config['hcaptcha_secret'] : '';
  }

  protected function visible($sitekey)
  {
    return '<div class="h-captcha" data-sitekey="' . $this->e($sitekey) . '"></div>' . "\n";
  }

  protected function invisible($sitekey, $options)
  {
    $this->counter++;

    $callback = 'cf_hcaptcha_submit_' . $this->counter;
    $button_text = isset($options['button_text']) ? (string) $options['button_text'] : 'Submit';

    return
      '<script>' . "\n"
      . 'function ' . $callback . '(token) {' . "\n"
      . '  var button = document.querySelector("[data-cf-hcaptcha-button=\'' . $callback . '\']");' . "\n"
      . '  if (button && button.form) {' . "\n"
      . '    button.form.submit();' . "\n"
      . '  }' . "\n"
      . '}' . "\n"
      . '</script>' . "\n"
      . '<button type="submit" class="h-captcha"'
      . ' data-sitekey="' . $this->e($sitekey) . '"'
      . ' data-size="invisible"'
      . ' data-callback="' . $this->e($callback) . '"'
      . ' data-cf-hcaptcha-button="' . $this->e($callback) . '">'
      . $this->e($button_text)
      . '</button>' . "\n";
  }

  protected function sitekey()
  {
    return isset($this->config['hcaptcha_sitekey']) ? (string) $this->config['hcaptcha_sitekey'] : '';
  }

  protected function e($value)
  {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
  }
}