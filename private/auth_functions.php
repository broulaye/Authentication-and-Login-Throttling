<?php

  // Will perform all actions necessary to log in the user
  // Also protects user from session fixation.
  function log_in_user($user) {
    session_regenerate_id();
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['last_login'] = time();
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
    return true;
  }

  // A one-step function to destroy the current session
  function destroy_current_session() {
    // TODO destroy the session file completely
  }

  // Performs all actions necessary to log out a user
  function log_out_user() {
    unset($_SESSION['user_id']);
    destroy_current_session();
    return true;
  }

  // Determines if the request should be considered a "recent"
  // request by comparing it to the user's last login time.
  function last_login_is_recent() {
    $recent_limit = 60 * 60 * 24 * 1; // 1 day
    if(!isset($_SESSION['last_login'])) { return false; }
    return (($_SESSION['last_login'] + $recent_limit) >= time());
  }

  // Checks to see if the user-agent string of the current request
  // matches the user-agent string used when the user last logged in.
  function user_agent_matches_session() {
    if(!isset($_SERVER['HTTP_USER_AGENT'])) { return false; }
    if(!isset($_SESSION['user_agent'])) { return false; }
    return ($_SERVER['HTTP_USER_AGENT'] === $_SESSION['user_agent']);
  }

  // Inspects the session to see if it should be considered valid.
  function session_is_valid() {
    if(!last_login_is_recent()) { return false; }
    if(!user_agent_matches_session()) { return false; }
    return true;
  }

  // is_logged_in() contains all the logic for determining if a
  // request should be considered a "logged in" request or not.
  // It is the core of require_login() but it can also be called
  // on its own in other contexts (e.g. display one link if a user
  // is logged in and display another link if they are not)
  function is_logged_in() {
    // Having a user_id in the session serves a dual-purpose:
    // - Its presence indicates the user is logged in.
    // - Its value tells which user for looking up their record.
    if(!isset($_SESSION['user_id'])) { return false; }
    if(!session_is_valid()) { return false; }
    return true;
  }

  // Call require_login() at the top of any page which needs to
  // require a valid login before granting acccess to the page.
  function require_login() {
    if(!is_logged_in()) {
      destroy_current_session();
      redirect_to(url_for('/staff/login.php'));
    } else {
      // Do nothing, let the rest of the page proceed
    }
  }

  function my_password_hash($password, $option) {

    if(!$option) {
      // Use bcrypt with a "cost" of 10
      $hash_format = "$2y$10$";
    } else {
      $hash_format = "$2y$". $option['cost'] . "$";
    }

    return crypt($password, $hash_format);
  }

  function my_password_verify($new_password, $real_password) {
    $password_hash = my_password_hash($new_password);
    $is_match = ($real_password === $password_hash);
    return $is_match;
  }

  function generate_strong_password($char_num) {
    if(!$char_num) {
      $char_num = 12;
    }
    $alphabet = 'abcdefghijklmnopqrstuvwxyz';
    $numbers = '1234567890';
    $symbol = '^£$%&*()}{@#~?><>,|=_+¬-';
    $capitalLetter = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $pass = array();
    $alphaLength = strlen($alphabet) - 1;
    $numbersLength = strlen($numbers) - 1;
    $symbolLength = strlen($symbol) - 1;
    $capitalLetterLength = strlen($capitalLetter) - 1;
    $n = rand(0, $capitalLetterLength);
    $pass[] = $capitalLetter[$n];
    $n = rand(0, $numbersLength);
    $pass[] = $numbers[$n];
    $n = rand(0, $symbolLength);
    $pass[] = $symbol[$n];
    for ($i = 0; $i < ($char_num-3); $i++) {
        $n = rand(0, $alphaLength);
        $pass[] = $alphabet[$n];
    }

    $result = implode($pass); //turn the array into a string

    return str_shuffle($result); //shuffle result before returning it
}

?>
