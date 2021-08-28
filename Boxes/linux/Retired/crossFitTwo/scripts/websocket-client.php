<?php

require 'vendor/autoload.php';

use WebSocket\Client;

$client = new WebSocket\Client("ws://gym.crossfit.htb/ws/");
$recv_token = $client->receive();
$token = json_decode($recv_token, true)["token"];
$payload = json_encode(array('message' => 'available', 'params' => $_GET['id'], 'token' => $token));
$client->send($payload);
echo $client->receive();
$client->close();

?>