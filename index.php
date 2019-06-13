<?php

define("SQRL_PHP_DIRPATH", "Trianglman/Sqrl/");
require_once SQRL_PHP_DIRPATH."include_classes.php";

$config = new \Trianglman\Sqrl\SqrlConfiguration();
$config->loadConfigFromJSON('config.json');
$storage = new \Trianglman\Sqrl\SqrlStoreStatelessAbstract();
$generator = new \Trianglman\Sqrl\SqrlGenerate($config, $storage);

//output the QR file to stdout
$generator->render();

//get the nonce for other uses, i.e. link, etc.
$nonce = $generator->getNonce();

print $nonce;

?>
