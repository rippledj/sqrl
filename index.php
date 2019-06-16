<?php

//trigger_error("Pancake Data Store Warning: ", E_USER_ERROR);
//define the path to Sqrl classes
define("SQRL_PHP_DIRPATH", "Sqrl/");
//load logging
require_once SQRL_PHP_DIRPATH."logging_controller.php";
//load vendor libraries
require_once "vendor/autoload.php";

//start a session
if (session_status() == PHP_SESSION_NONE) {
  session_start();
}

/* Sandbox Mode */
if($_SERVER["SERVER_ADDR"] == $_SERVER["REMOTE_ADDR"]){
  $config_filepath = 'config/config_localhost.json';
  require_once SQRL_PHP_DIRPATH.'config/db_config_localhost.php';
}else{
  $config_filepath = 'config/config.json';
  require_once SQRL_PHP_DIRPATH.'config/db_config.php';
}

//require all classes for generating SQRL login items
require_once SQRL_PHP_DIRPATH."include_login_classes.php";

//create config object
$config = new \Sqrl\SqrlConfiguration(SQRL_PHP_DIRPATH.$config_filepath);
//create database object
$database = new \Sqrl\SqrlDatabase();
//create SQRL generator object
$generator = new \Sqrl\SqrlGenerate($config, $database);
$url = $generator->getUrl();
//output the QR file to stdout
$generator->render("qrcode.png");
//get the nonce for other uses, i.e. link, etc.
$nonce = $generator->getNut();

?>
<head>
   <link rel="stylesheet" href="css/style.css">
</head>
<body>
  <center>
  <?php echo $url; ?></br>
  <div id="sqrl_login_div" class="tooltip">
    <a href="<?php echo $url; ?>">
      <img id="sqrl_login_logo" src="images/login_button.svg">
    </a>
    <span class="tooltiptext"><img src="qrcode.png"></span>
  </div>
  </center>
</body>
