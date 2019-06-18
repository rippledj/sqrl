<?php

define("SQRL_PHP_DIRPATH", "Sqrl/");

//require vendor packages
require_once "vendor/autoload.php";

/* Sandbox Mode */
if($_SERVER["SERVER_ADDR"] == $_SERVER["REMOTE_ADDR"]){
  $config = SQRL_PHP_DIRPATH.'config/config_localhost.json';
}else{
  $config = SQRL_PHP_DIRPATH.'config/config.json';
}

//start a session
if (session_status() == PHP_SESSION_NONE) {
  session_start();
}

// Include Exception Class
require_once SQRL_PHP_DIRPATH."SqrlException.php";
// Include SqrlGenerate Class
require_once SQRL_PHP_DIRPATH."Sqrl.php";

//create SQRL generator object
$sqrl = new \Sqrl\Sqrl($config);
trigger_error("SQRL Login Nut Generation - ", E_USER_NOTICE);

$url = $sqrl->getUrl();
//get the nonce for other uses, i.e. link, etc.
$nut = $sqrl->getNut();
//output the QR file to stdout
//$sqrl->render("images/qr_codes/".$nut.".png");
//clear expired nuts
$sqrl->clearExpiredNuts();

?>
<head>
   <link rel="stylesheet" href="css/style.css">
   <script type="text/javascript" src="js/qrcode.min.js"></script>
</head>
<body>
  <center>
  <?php echo $url; ?></br>
  <div id="sqrl_login_div" class="tooltip">
    <a href="<?php echo $url; ?>">
      <img id="sqrl_login_logo" src="images/login_button.svg">
    </a>
    <span class="tooltiptext"><div id="qrcode"></div></span>
  </div>
  </center>
</body>
<script type="text/javascript">
var qrcode = new QRCode(document.getElementById("qrcode"), {
    text: "<?php echo $url; ?>",
    width: 250,
    height: 250,
    colorDark : "#00304d",
    colorLight : "#ffffff",
    correctLevel : QRCode.CorrectLevel.H
});
</script>
