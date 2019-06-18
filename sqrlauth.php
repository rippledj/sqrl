<?php

//define the path to Sqrl classes
define("SQRL_PHP_DIRPATH", "Sqrl/");

//load logging controller
require_once SQRL_PHP_DIRPATH."logging_controller.php";

require_once "vendor/autoload.php";

/* Sandbox Mode */
if($_SERVER["SERVER_ADDR"] == $_SERVER["REMOTE_ADDR"]){
  $config = SQRL_PHP_DIRPATH.'config/config_localhost.json';
  require_once SQRL_PHP_DIRPATH.'config/db_config_localhost.php';
}else{
  $config = SQRL_PHP_DIRPATH.'config/config.json';
  require_once SQRL_PHP_DIRPATH.'config/db_config.php';
}

//include Exception Class
require_once SQRL_PHP_DIRPATH."SqrlException.php";
//include SqrlStoreDatabase
require_once SQRL_PHP_DIRPATH."SqrlDatabase.php";
//include SqrlGenerate Class
require_once SQRL_PHP_DIRPATH."Sqrl.php";

//trigger notice that page was loaded
trigger_error("SQRL Login Authentication Request - ", E_USER_NOTICE);

//start a session
if (session_status() == PHP_SESSION_NONE) {
  session_start();
}

//create SQRL object
$sqrl = new \Sqrl\Sqrl($config, $database);
$requestHandler->parseRequest($_GET, $_POST, $_SERVER);

//check validation
$response = $requestHandler->getResponseMessage();
trigger_error("SQRL Login Authentication Request Response - ".$response, E_USER_NOTICE);

?>
