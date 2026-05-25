<?php

namespace classicframework\captcha;

class Captcha
{
  protected $config = array();
  protected $driver = null;
  protected $counter = 0;
  protected $session = null;

  public function __construct($config = array(), $session = null)
  {
    $this->config = is_array($config) ? $config : array();
    $this->session = $session;
  }

  public function head()
  {
    if (!$this->enabled()) {
      return '';
    }

    $driver = $this->driver();

    if ($driver !== null) {
      return $driver->head();
    }

    return $this->simple_head();
  }

  public function body($options = array())
  {
    if (!$this->enabled()) {
      return '';
    }

    $options = is_array($options) ? $options : array();

    $driver = $this->driver();

    if ($driver !== null) {
      return $driver->body($options);
    }

    return $this->simple_body($options);
  }

  public function verify($data = null, $remote_ip = null)
  {
    if (!$this->enabled()) {
      return true;
    }

    if ($data === null) {
      $data = $_POST;
    }

    if (!is_array($data)) {
      return false;
    }

    $driver = $this->driver();

    if ($driver !== null && method_exists($driver, 'verify')) {
      return $driver->verify($data, $remote_ip);
    }

    return $this->simple_verify($data);
  }

  protected function driver()
  {
    if ($this->driver !== null) {
      return $this->driver;
    }

    foreach ($this->config as $key => $value) {
      if (substr($key, -8) !== '_enabled') {
        continue;
      }

      if ($key === 'enabled') {
        continue;
      }

      if ($value !== true) {
        continue;
      }

      $name = substr($key, 0, -8);
      $class = __NAMESPACE__ . '\\' . ucfirst($name);

      if (class_exists($class)) {
        $this->driver = new $class($this->config);
        return $this->driver;
      }
    }

    return null;
  }

  protected function simple_head()
  {
    $html = '';

    $html .= '<script>' . "\n";
    $html .= '(function () {' . "\n";
    $html .= '  document.addEventListener(\'submit\', function (event) {' . "\n";
    $html .= '    var form = event.target;' . "\n";
    $html .= '    var captchas = form.querySelectorAll(\'.cf-captcha\');' . "\n";
    $html .= '    var i;' . "\n";
    $html .= "\n";
    $html .= '    for (i = 0; i < captchas.length; i++) {' . "\n";
    $html .= '      if (' . "\n";
    $html .= '        captchas[i].className.indexOf(\'cf-captcha-invisible\') !== -1' . "\n";
    $html .= '        && captchas[i].style.display !== \'block\'' . "\n";
    $html .= '      ) {' . "\n";
    $html .= '        captchas[i].style.display = \'block\';' . "\n";
    $html .= '        event.preventDefault();' . "\n";
    $html .= '        return false;' . "\n";
    $html .= '      }' . "\n";
    $html .= '    }' . "\n";
    $html .= '  }, false);' . "\n";
    $html .= '}());' . "\n";
    $html .= '</script>' . "\n";

    $html .= '<style>' . "\n";
    $html .= '.cf-captcha-invisible {' . "\n";
    $html .= '  display: none;' . "\n";
    $html .= '}' . "\n";
    $html .= '</style>' . "\n";

    return $html;
  }

  protected function simple_body($options)
  {
    $this->counter++;

    $mode = isset($options['mode']) ? (string) $options['mode'] : 'visible';

    $a = mt_rand(1, 9);
    $b = mt_rand(1, 9);
    $answer = $a + $b;

    $token = $this->random_token(16);

    if (is_object($this->session)) {
      $this->session->set('_captcha_' . $token, (string) $answer);
    }

    $id = 'cf-captcha-' . $this->counter;
    $class = 'cf-captcha';

    if ($mode === 'invisible') {
      $class .= ' cf-captcha-invisible';
    }

    return
      '<div id="' . $this->e($id) . '" class="' . $this->e($class) . '">' . "\n"
      . '  <label>' . $this->e((string) $a . ' + ' . (string) $b . ' = ?') . '</label>' . "\n"
      . '  <input type="text" name="_captcha_answer" class="cf-captcha-answer" autocomplete="off">' . "\n"
      . '  <input type="hidden" name="_captcha_token" class="cf-captcha-token" value="' . $this->e($token) . '">' . "\n"
      . '</div>' . "\n";
  }

  protected function simple_verify($data)
  {
    if (!is_object($this->session)) {
      return false;
    }

    if (!isset($data['_captcha_token']) || !isset($data['_captcha_answer'])) {
      return false;
    }

    $token = (string) $data['_captcha_token'];
    $answer = trim((string) $data['_captcha_answer']);

    $expected = $this->session->get('_captcha_' . $token, null);
    $this->session->delete('_captcha_' . $token);

    if ($expected === null) {
      return false;
    }

    return $this->compare($answer, (string) $expected);
  }

  protected function enabled()
  {
    return isset($this->config['enabled']) ? (bool) $this->config['enabled'] : true;
  }

  protected function e($value)
  {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
  }

  protected function random_token($bytes)
  {
    $bytes = (int) $bytes;

    if (function_exists('random_bytes')) {
      return bin2hex(random_bytes($bytes));
    }

    if (function_exists('openssl_random_pseudo_bytes')) {
      return bin2hex(openssl_random_pseudo_bytes($bytes));
    }

    return sha1(uniqid(mt_rand(), true) . microtime(true));
  }

  protected function compare($a, $b)
  {
    $a = (string) $a;
    $b = (string) $b;

    if (function_exists('hash_equals')) {
      return hash_equals($a, $b);
    }

    if (strlen($a) !== strlen($b)) {
      return false;
    }

    $result = 0;

    for ($i = 0; $i < strlen($a); $i++) {
      $result |= ord($a[$i]) ^ ord($b[$i]);
    }

    return $result === 0;
  }
}