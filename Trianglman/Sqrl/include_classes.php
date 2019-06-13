<?php

// Include all required classes
//
// Include Exception Class
require_once SQRL_PHP_DIRPATH."SqrlException.php";
// Include Crypto Class
require_once SQRL_PHP_DIRPATH."Ed25519/CryptoInterface.php";
require_once SQRL_PHP_DIRPATH."Ed25519/Crypto.php";
// Include Traits Class
require_once SQRL_PHP_DIRPATH."Traits/SqrlURLGenerator.php";
require_once SQRL_PHP_DIRPATH."Traits/Base64Url.php";
// Include Nonce Validator Class
require_once SQRL_PHP_DIRPATH."NonceValidatorInterface.php";
require_once SQRL_PHP_DIRPATH."SodiumNonceValidator.php";
// Include SqrlConfiguration
require_once SQRL_PHP_DIRPATH."SqrlConfiguration.php";
// Include SqrlStoreInterface Interface
require_once SQRL_PHP_DIRPATH."SqrlStoreInterface.php";
require_once SQRL_PHP_DIRPATH."SqrlStoreStatelessAbstract.php";
// Include SqrlGenerate Class
require_once SQRL_PHP_DIRPATH."SqrlGenerateInterface.php";
require_once SQRL_PHP_DIRPATH."SqrlGenerate.php";
// Include Request Handler Class
require_once SQRL_PHP_DIRPATH."SqrlRequestHandlerInterface.php";
require_once SQRL_PHP_DIRPATH."SqrlRequestHandler.php";
// Include SqrlGenerate Class
require_once SQRL_PHP_DIRPATH."SqrlValidateInterface.php";
require_once SQRL_PHP_DIRPATH."SqrlValidate.php";



?>
