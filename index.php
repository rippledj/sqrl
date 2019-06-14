<?php

define("SQRL_PHP_DIRPATH", "Trianglman/Sqrl/");
require_once SQRL_PHP_DIRPATH."include_classes.php";
require_once "vendor/autoload.php";

$config = new \Trianglman\Sqrl\SqrlConfiguration();
$config->loadConfigFromJSON('config.json');
$storage = new \Trianglman\Sqrl\SqrlStoreStateless();
$generator = new \Trianglman\Sqrl\SqrlGenerate($config, $storage);

//output the QR file to stdout
$generator->render("qrcode.png");

//get the nonce for other uses, i.e. link, etc.
$nonce = $generator->getNonce();

echo "Nonce: ".$nonce."</br></br>";

?>

<img src="qrcode.png">
