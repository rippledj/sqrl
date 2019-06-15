<?php

/**
 * Logger Initialization Controller
 * Vanilla Pancakes Web-App Framework
 *
 ***/

//TODO: create try catch for the exception_handler in case the handler is not
// able to write error, print a message to front end to check permissions of file.

// require_once logging config files;
require_once "config/logging_config.php";

// Set error reporting according to config values; display `On` for sandbox mode
// otherwise display errors `Off`
$display_errors = "Off";
$display_startup_errors = "Off";

// Apply config rules to error reporting; always set `on`
error_reporting(-1); // -1 for reporting, 1 for none (Always set to -1)
ini_set('display_errors', $display_errors);
ini_set('display_startup_errors', $display_startup_errors);

// Set the error log file and turn on file-based error logging
ini_set("log_errors", 1); // (Always set to `1` for logging)
ini_set("error_log", ERROR_LOG); // ERROR_LOG in the logging_config.php file defines where logs are stored.

// Define exception handler
function exception_handler($exception){

  // TODO: find way to set $log_level depending on the E_USER_NOTICE, E_USER_WARNING, E_USER_ERROR
  // for now set $log_level to `EXCEPTION`
  $log_level = "Exception";
  try{
    echo "<b>Vanilla Pancakes ".$log_level."</b>: " , $exception->getMessage()." in <b>".$exception->getFile()."</b> on line <b>".$exception->getLine()."</b><br><br>";
    error_log("[".date('Y-m-d H:i:s e')."] "."Vanilla Pancakes ".$log_level.": ".$exception->getMessage()." in ".$exception->getFile()." on line ".$exception->getLine()."\n", 3, ERROR_LOG);
  }catch (Exception $e){
    echo "\nVanilla Pancakes Logging Error: Check permissions of ".APP_ROOT_DIR."/".ERROR_LOG , $exception->getMessage(), "\n\n";
  }
}

// Define the default exception handler
// this allows exceptions to be directed to log file and stdout
set_exception_handler('exception_handler');

// Define the error handler
function error_handler($errno, $errstr, $errfile, $errline){

  // Set the initial log_level variable to null
  $log_level = NULL;
  // Set the log_level string according to $errno.  $log_level refers to setting of
  // ERROR_LOG_LEVEL_FILE in recipe_booklogging_config.php.
  if($errno == 2) { $log_level_string = "Warning: "; $log_level = 2; }
  elseif($errno == 1024) { $log_level_string = "Notice: "; $log_level = 3; }
  elseif($errno == 512) { $log_level_string = "Error: "; $log_level = 1; }
  elseif($errno == 8) { $log_level_string = "Notice: "; $log_level = 3; }
  elseif($errno == 8192) { $log_level_string = "Notice: "; $log_level = 3; }
  elseif($errno = 256){ $log_level_string = "Error: "; $log_level = 1; }
  else { $log_level_string = "Error: "; $log_level = 1; }

  // Set the error to log to file if the config setting level is set appropriately
  if(ERROR_LOG_LEVEL_FILE != 0 && ((ERROR_LOG_LEVEL_FILE >= 1 && $log_level == 1) || (ERROR_LOG_LEVEL_FILE >= 2 && $log_level == 2) || (ERROR_LOG_LEVEL_FILE == 3 && $log_level == 3))){
    try{
      // Log the message to file
      error_log("[".date('Y-m-d H:i:s e')."] "."Vanilla Pancakes ".$log_level_string.": ".$errstr. " in ".$errfile." on line ".$errline."\n", 3, ERROR_LOG);
    }catch(Exception $e){
      echo "\nLogging Error: Check permissions of ".APP_ROOT_DIR."/".ERROR_LOG , $exception->getMessage(), "\n\n";
    }
  }

  // Set the error to log to stdout if the config setting level is set appropriately
  if(ERROR_LOG_LEVEL_STDOUT != 0 && ((ERROR_LOG_LEVEL_STDOUT >= 1 && $log_level == 1) || (ERROR_LOG_LEVEL_STDOUT >= 2 && $log_level == 2) || (ERROR_LOG_LEVEL_STDOUT == 3 && $log_level == 3))){
    try{
      // Log the message to stdout
      echo "<b>Vanilla Pancakes ".$log_level_string."</b>: ".$errstr." in <b>".$errfile."</b> on line <b>".$errline."</b><br><br>";
    }catch(Exception $e){
      echo "\nLogging Error: Check permissions of ".APP_ROOT_DIR."/".ERROR_LOG , $exception->getMessage(), "\n\n";
    }
  }


}
// Define the default error handler and error handler funcitons
// this allows errors to be directed to log file and stdout
set_error_handler('error_handler');


?>
