<?php

//define the path to Sqrl classes
define("SQRL_PHP_DIRPATH", "Sqrl/");

//require vendor libraries
require_once "vendor/autoload.php";

/* Sandbox Mode */
if($_SERVER["SERVER_ADDR"] == $_SERVER["REMOTE_ADDR"]){
  $config = SQRL_PHP_DIRPATH.'config/config_localhost.json';
}else{
  $config = SQRL_PHP_DIRPATH.'config/config.json';
}

//include Exception Class
require_once SQRL_PHP_DIRPATH."SqrlException.php";
//include SqrlGenerate Class
require_once SQRL_PHP_DIRPATH."Sqrl.php";

//start a session
if (session_status() == PHP_SESSION_NONE) {
  session_start();
}

//create SQRL object
$sqrl = new \Sqrl\Sqrl($config);
trigger_error("SQRL Login Request - ", E_USER_NOTICE);

//TODO: write sanitize functions
$sqrl->sanitizeClientRequest($_GET, $_POST, $_SERVER);
require_once SQRL_PHP_DIRPATH."pretty_print.php";
//analyze Sqrl client response
$sqrl->parseRequest($_GET, $_POST, $_SERVER);
//respond to validation request
$response = $sqrl->getResponseMessage();
echo $response;
trigger_error("SQRL Login Authentication Request Response - ".$response, E_USER_NOTICE);

?>
