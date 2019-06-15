<?php

define("SQRL_PHP_DIRPATH", "Sqrl/");
require_once SQRL_PHP_DIRPATH."include_auth_classes.php";
require_once "vendor/autoload.php";

$config = new \Sqrl\SqrlConfiguration();
$config->loadConfigFromJSON('config.json');
$storage = new \Sqrl\SqrlStoreDatabase();
$validator = new \Sqrl\SqrlValidate($config, $validator, $storage);
$validator->setValidator(new \Sqrl\ed25519\Crypto());

//initialize the request handler
$requestResponse = new \Sqrl\SqrlRequestHandler($validator);
$requestResponse->parseRequest($_GET, $_POST, $_SERVER);

//check validation
$requestResponse = $obj->getResponseMessage();
$requestResponseCode = $obj->getResponseCode();


?>
