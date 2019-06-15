<?php

/**
* Logging Configurations
* Vanilla Pancakes Web-App Framework
*
***/

// Logging directory config
// TODO: setup a log roll and compression in live site
define("ERROR_LOG", "log/error.log");

// Set the logging level for logging to file
// 0=none, 1=low, 2=medium, 3=verbose
define("ERROR_LOG_LEVEL_FILE", 3);

// Set the logging level to stdout
// 0=none, 1=low, 2=medium, 3=verbose
// SANDBOX_MODE will automatically set stdout errors to none
define("ERROR_LOG_LEVEL_STDOUT", 0);

?>
