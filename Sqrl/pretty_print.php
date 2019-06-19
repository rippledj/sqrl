<?php

trigger_error("<pre>".print_r($_GET,true)."</pre>", E_USER_NOTICE);
trigger_error("<pre>".print_r($_POST,true)."</pre>", E_USER_NOTICE);
trigger_error("<pre>".print_r($_SERVER,true)."</pre>", E_USER_NOTICE);

$response = "<pre>".print_r($_GET,true).print_r($_POST,true).print_r($_SERVER,true)."</pre>";
$reponse_file = fopen('response.php', 'w') or die('Cannot open file:  '.$my_file); //implicitly creates file
fwrite($reponse_file, $response);
fclose($reponse_file);
