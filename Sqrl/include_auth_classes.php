<?php

// Include all required authentication classes
//
// Include Exception Class
require_once SQRL_PHP_DIRPATH."SqrlException.php";
// Include Crypto Class
require_once SQRL_PHP_DIRPATH."Ed25519/Crypto.php";
// Include Traits Class
require_once SQRL_PHP_DIRPATH."Traits/SqrlURLGenerator.php";
require_once SQRL_PHP_DIRPATH."Traits/Base64Url.php";
// Include Nonce Validator Class
require_once SQRL_PHP_DIRPATH."SodiumNonceValidator.php";
// Include SqrlConfiguration
require_once SQRL_PHP_DIRPATH."SqrlConfiguration.php";
// Include SqrlStoreDatabase
require_once SQRL_PHP_DIRPATH."SqrlStoreDatabase.php";
// Include Request Handler Class
require_once SQRL_PHP_DIRPATH."SqrlRequestHandler.php";
// Include SqrlGenerate Class
require_once SQRL_PHP_DIRPATH."SqrlValidate.php";



?>
