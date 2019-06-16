<?php

define("SQRL_PHP_DIRPATH", "Sqrl/");
require_once SQRL_PHP_DIRPATH."include_auth_classes.php";
require_once "vendor/autoload.php";

$config = new \Sqrl\SqrlConfiguration(SQRL_PHP_DIRPATH.'config/config.json');
$database = new \Sqrl\SqrlDatabase();
$validator = new \Sqrl\SqrlValidate($config, $database);

//initialize the request handler
$requestHandler = new \Sqrl\SqrlRequestHandler($config, $database, $validator);
$requestHandler->parseRequest($_GET, $_POST, $_SERVER);

//check validation
$response = $requestHandler->getResponseMessage();
echo $response;

?>
