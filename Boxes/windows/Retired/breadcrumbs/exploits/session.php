<?php

/*
First run "composer require firebase/php-jwt"
*/

require __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;

$username = "paul";

function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;

}

echo makesession($username) . "\n";

$secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';

$payload = array(
    "data" => array(
        "username" => $username
));

$jwt = JWT::encode($payload, $secret_key, 'HS256');
echo $jwt . "\n";

// $decoded = JWT::decode($jwt, $secret_key, array('HS256'));
// var_dump($decoded);
// echo $decoded;
?>