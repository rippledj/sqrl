<?php
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 John Judy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Sqrl;
use Endroid\QrCode\QrCode;
use PDO;

/**
 * Generates a SQRL QR image, URL and nonce.
 */
class Sqrl
{

    /**
     * @var string
     */
    protected $nonce = '';

    /*
     * Database variables
     *
     *
    */

    /**
     * @var object $db_connection The database connection for each db
     */
    public $conn = null; // connection for application system data

    /**
     * @var object $db_status The database connection status for each db
     */
    public $db_status = null; // status of application system data connection

    /*
     * Config variables
     *
     *
    */

    /**
     * The versions this SQRL server supports
     *
     * Defaults to only accepting version 1
     *
     * @var array[]mixed
     */
    protected $acceptedVersions = [];
    /**
     * Whether responses to the server should be secure
     *
     * Defaults to false
     *
     * @var boolean
     */
    protected $secure = false;
    /**
     * The domain clients should generate a key for
     * This can include subdirectories of a web domain in order to allow sites managed
     * by subdirectories to use different SQRL keying material for the same user
     *
     * Required if generating the SQRL URLs and validating responses
     *
     * @var string
     */
    protected $domain = '';
    /**
     * Path to the authentication script
     * This is appended to the $domain value when generating SQRL URLs
     *
     * Required if generating SQRL URLs and validating responses
     *
     * @var string
     */
    protected $authenticationPath = '';
    /**
     * Whether users are allowed to generate anonymous accounts
     *
     * If a user with an unrecognized identification key attempts to authenticate,
     * should the site accept just the key as a user identification
     *
     * Defaults to false
     *
     * @var boolean
     */
    protected $anonAllowed = false;
    /**
     * Time in minutes that a nonce is considered valid
     *
     * Default 5
     *
     * @var int
     */
    protected $nonceMaxAge = 5;
    /**
     * Height, in pixels, of a generated QR code
     *
     * Default 300
     *
     * @var int
     */
    protected $qrHeight = 300;
    /**
     * Padding, in pixels, around a generated QR code
     *
     * Default 10
     *
     * @var int
     */
    protected $qrPadding = 10;
    /**
     * Random string used to salt generated nonces
     *
     * @var string
     */
    protected $nonceSalt = 'random data';

    /**
     * Random string used as initialization vector to generated nonces
     *
     * @var string
     */
    protected $iv = 'random data';

    /*
     * Request handler variabless
     *
     *
    */

    //TIF Codes
    /**
     * 	When set, this bit indicates that the web server has
     * found an identity association for the user based upon the default (current)
     * identity credentials supplied by the client: the IDentity Key (IDK) and
     * the IDentity Signature (IDS).
     *
     * @const
     * @var int
     */
    const ID_MATCH = 0x01;

    /**
     * When set, this bit indicates that the web server has found an identity
     * association for the user based upon the previous identity credentials
     * supplied by the client: the previous IDentity Key (pIDK) and the previous
     * IDentity Signature (pIDS).
     *
     * @const
     * @var int
     */
    const PREVIOUS_ID_MATCH = 0x02;

    /**
     * When set, this bit indicates that the IP address of the entity which
     * requested the initial logon web page containing the SQRL link URL (and
     * probably encoded into the SQRL link URL's “nut”) is the same IP address
     * from which the SQRL client's query was received for this reply.
     *
     * @const
     * @var int
     */
    const IP_MATCH = 0x04;

    /**
     * When set, the account associated with the identified user is disabled for
     * SQRL-initiated authentication without the additional Rescue Code-derived
     * unlock request signature (urs). If the 'query' command returns with this
     * tif bit set, and the SQRL client does not already have the Rescue Code in
     * RAM, it should inform its user that they will need to supply their
     * identity' Rescue Code in order to proceed with the authentication
     * operation.
     *
     * @const
     * @var int
     */
    const SQRL_DISABLED = 0x08;

    /**
     * This bit indicates that the client requested one or more standard SQRL
     * functions (through command verbs) that the server does not currently
     * support. The client will likely need to advise its user that whatever
     * they were trying to do is not possible at the target website. The SQRL
     * server will fail this query, thus also setting the “40h” Command Failed
     * bit.
     *
     * @const
     * @var int
     */
    const FUNCTION_NOT_SUPPORTED = 0x10;

    /**
     * The server replies with this bit set to indicate that the client's
     * signature(s) are correct, but something about the client's query
     * prevented the command from completing. This is the server's way of
     * instructing the client to retry and reissue the immediately previous
     * command using the fresh ‘nut=’ crypto material and ‘qry=’ url the server
     * has also just returned in its reply. Although we don't want to overly
     * restrict the specification of this error, the trouble is almost certainly
     * static, expired, or previously used nut= or qry= data. Thus, reissuing
     * the previous command under the newly supplied server parameters would be
     * expected to succeed. The “0x40” “Command failed” bit (shown next) will
     * also be set since the client's command will not have been processed.
     *
     * @const
     * @var int
     */
    const TRANSIENT_ERROR = 0x20;

    /**
     * When set, this bit indicates that the web server had a problem
     * successfully processing the client's query. In any such case, no change
     * will be made to the user's account status. All SQRL server-side actions
     * are atomic. This means that either everything succeeds or nothing is
     * changed. This is important since clients can request multiple updates and
     * changes at once.
     *
     * If this bit is set without the 80h bit set (see below) the trouble was
     * not with the client's provided data, protocol, etc. but with some other
     * aspect of completing the client's request. With the exception of the
     * following “Client failure” status bit, the SQRL semantics do not attempt
     * to enumerate every conceivable web server failure reason. The web server
     * is free to use the “ask” command without arguments to explain the problem
     * to the client's user.
     *
     * @const
     * @var int
     */
    const COMMAND_FAILED = 0x40;

    /**
     * This bit is set by the server when some aspect of the client's submitted
     * query ‑ other than expired but otherwise valid transaction state
     * information ‑ was incorrect and prevented the server from understanding
     * and/or completing the requested action. This could be the result of a
     * communications error, a mistake in the client's SQRL protocol, a
     * signature that doesn't verify, or required signatures for the requested
     * actions which are not present. And more specifically, this is NOT an
     * error that the server knows would likely be fixed by having the client
     * silently reissue it previous command . . . although that might still be
     * the first recouse for the client. This is NOT an error Since any such
     * client failure will also result in a failure of the command, the 40h bit
     * will also be set.
     *
     * @const
     * @var int
     */
    const CLIENT_FAILURE = 0x80;

    /**
     * This bit is set by the server when a SQRL identity which may be associated
     * with the query nut does not match the SQRL ID used to submit the query.
     * If the server is maintaining session state, such as a logged on session,
     * it may generate SQRL query nuts associated with that logged-on session's
     * SQRL identity. If it then receives a SQRL query using that nut, but issued
     * with a different SQRL identity, it should fail the command (with the 0x40
     * bit) and also return this 0x100 error bit so that the client may inform
     * its user that the wrong SQRL identity was used with a nut that was
     * already associated with a different identity.
     *
     * @const
     * @var int
     */
    const BAD_ID_ASSOCIATION = 0x100;

    protected $ipMatch = false;
    protected $actions = array();
    protected $clientOptions = array();
    protected $responseCode = 200;
    protected $tif = 0x0;
    protected $authenticationKey = '';
    protected $clientSUK = '';
    protected $clientVUK = '';
    protected $requestNut = '';
    protected $previousIdKey = '';


    public function __construct(string $config)
    {
        $this->loadConfigFromJSON($config);
        $this->setupLogger();
        $this->databaseConnect();

    }

    public function getUrl(): string
    {
        return $this->generateUrl($this->generateNut());
    }

    public function render(?string $outputFile = null)
    {
        $qrCode = new QrCode();
        $qrCode->setText($this->getUrl());
        $qrCode->setSize($this->getQrHeight());
        $qrCode->setPadding($this->getQrPadding());
        $qrCode->render($outputFile);
    }

    /**
     * Generates a random, one time use key to be used in the sqrl validation
     *
     * The implementation of this may get more complicated depending on the
     * requirements detailed in any reference implementation. Users wanting to
     * make this library more (or less) secure should override this function
     * to strengthen (or weaken) the randomness of the generation.
     *
     * @return string
     */
     protected function generateNut()
     {

          $this->nut = substr(md5(uniqid('', true)), 0, 12);
          // Store the nut
          if(!$this->storeIssuedNutRecord((string) $this->nut, (string) $_SERVER['REMOTE_ADDR'], (string) session_id())){
            throw new SqrlException(DATABASE_EXCEPTION);
          }else{

            return $this->nut;
          }

     }

    /**
     * Generates the URL for client responses
     *
     * @param string $nut
     * @return string
     */
    protected function generateUrl(string $nut): string
    {
        //build first character of url depending on secure or not
        if($this->getSecure() > 0 || $_SERVER['HTTPS']) $url = 'sqrl://';
        else $url = 'qrl://';
        //build the base Sqrl url
        $url .= $this->getDomain().$this->getAuthenticationPath().'?nut='.$nut;
        //calculate the extention onto the base domain (x value)
        if (strpos($this->getDomain(), '/') !== false) {
            $path_extension = strlen($this->getDomain())-strpos($this->getDomain(), '/');
            $url .= '&x='.$path_extension;
        }

        return $url;
    }

    /**
     * Returns the generated nonce
     *
     * @param int    $action [Optional] The type of action this nonce is being generated for
     * @param string $key [Optional] The public key associated with the nonce
     * @param string $previousNonce [Optional] The previous nonce in the transaction that should be associated to this nonce
     *
     * @return string The one time use string for the QR link
     */
    public function getNut(int $action = 0, string $key = '', string $previousNonce = ''): string
    {
        return $this->nut;
    }

    /**
     * Gets the user's IP address
     *
     * @return string
     */
    protected function getIp(): string
    {
      if (filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
        return $_SERVER['REMOTE_ADDR'];
      } else {
        return false;
      }
    }

    /**
     * Gets the user's current session ID
     *
     * @return string
     */
    protected function getCurrentSessionId(): string
    {
      //return the session id of current session
      return session_id();
    }

    /**
     * Gets the session information that matches the supplied session ID
     *
     * @param string $sessionId
     *
     * @return array
     */
    protected function getSessionInfo($sessionId)
    {
      return $_SESSION;
    }

    /**
     * Convert a string to a base64url encoded string
     * @param $string
     * @return string
     */
    protected function base64UrlEncode(string $string): string
    {
        $base64 = base64_encode($string);
        $urlencode = str_replace(['+', '/'], ['-', '_'], $base64);
        return trim($urlencode, '=');
    }

    /**
     * Base 64 URL decodes a string
     *
     * Basically the same as base64 decoding, but replacing URL safe "-" with "+"
     * and "_" with "/". Automatically detects if the trailing "=" padding has
     * been removed.
     *
     * @param string $string
     * @return string
     */
    protected function base64UrlDecode(string $string): string
    {
        $len = strlen($string);
        if($len%4 > 0){
            $string = str_pad($string, 4-($len%4), '=');
        }
        $base64 = str_replace(array('-','_'), array('+','/'), $string);
        return base64_decode($base64);
    }


    /**
     * Adds a nut to the user's current session
     *
     * @param string $newNut
     *
     * @return void
     */
    protected function addSessionNut($newNut,$sessionId)
    {
        $sessionInfo = $this->getSessionInfo($sessionId);
        $currentNuts = isset($sessionInfo['sqrl_nuts'])?explode(';',$sessionInfo['sqrl_nuts']):array();
        $currentNuts[] = $newNut;
    }

    public function loadConfigFromJSON(string $filePath): void
    {
        if (!file_exists($filePath)) {
            throw new \InvalidArgumentException('Configuration file not found');
        }
        $data = file_get_contents($filePath);
        $decoded = json_decode($data);
        if (is_null($decoded)) {
            throw new \InvalidArgumentException('Configuration data could not be parsed. Is it JSON formatted?');
        }
        if (is_array($decoded->accepted_versions)) {
            $this->setAcceptedVersions($decoded->accepted_versions);
        }
        $this->setSecure(!empty($decoded->secure) && (int)$decoded->secure > 0);
        $this->setDomain($decoded->key_domain ?? '');
        $this->setAuthenticationPath($decoded->authentication_path ?? '');
        $this->setAnonAllowed(
                !empty($decoded->allow_anonymous_accounts) && (int)$decoded->allow_anonymous_accounts > 0
                );
        if (!empty($decoded->nonce_max_age)) {
            $this->setNonceMaxAge($decoded->nonce_max_age);
        }
        if (!empty($decoded->height)) {
            $this->setQrHeight($decoded->height);
        }
        if (!empty($decoded->padding)) {
            $this->setQrPadding($decoded->padding);
        }
        if (!empty($decoded->db_host)) {
            $this->db_host = $decoded->db_host;
        }else{
          throw new \InvalidArgumentException('Database host not found in configuration file');
        }
        if (!empty($decoded->db_application)) {
            $this->db_application = $decoded->db_application;
        }else{
          throw new \InvalidArgumentException('Database name not found in configuration file');
        }
        if (!empty($decoded->db_name)) {
            $this->db_name = $decoded->db_name;
        }else{
          throw new \InvalidArgumentException('Database name not found in configuration file');
        }
        if (!empty($decoded->db_username)) {
            $this->db_username = $decoded->db_username;
        }else{
          throw new \InvalidArgumentException('Database username not found in configuration file');
        }
        if (!empty($decoded->db_password)) {
            $this->db_password = $decoded->db_password;
        }else{
          throw new \InvalidArgumentException('Database password not found in configuration file');
        }
        if (!empty($decoded->error_log)) {
            $this->error_log = $decoded->error_log;
        }else{
          throw new \InvalidArgumentException('Database password not found in configuration file');
        }
        $this->setNonceSalt(!empty($decoded->nonce_salt)?$decoded->nonce_salt:'');
        $this->setNonceIv(!empty($decoded->iv)?$decoded->iv:'');
    }

    /**
     * Gets the versions this SQRL server supports
     *
     * @return array
     */
    public function getAcceptedVersions(): array
    {
        return $this->acceptedVersions;
    }

    /**
     * Gets whether responses to the server should be secure
     *
     * @return boolean
     */
    public function getSecure(): bool
    {
        return $this->secure;
    }

    /**
     * Gets the domain clients should generate a key for
     *
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain;
    }

    /**
     * Gets the path to the authentication script
     *
     * @return string
     */
    public function getAuthenticationPath(): string
    {
        return $this->authenticationPath;
    }

    /**
     * Gets whether users are allowed to generate anonymous accounts
     *
     * @return boolean
     */
    public function getAnonAllowed(): bool
    {
        return $this->anonAllowed;
    }

    /**
     * Gets the time in minutes that a nonce is considered valid
     *
     * @return int
     */
    public function getNonceMaxAge(): int
    {
        return $this->nonceMaxAge;
    }

    /**
     * Gets the height, in pixels, of a generated QR code
     *
     * @return int
     */
    public function getQrHeight(): int
    {
        return $this->qrHeight;
    }

    /**
     * Gets the padding, in pixels, around a generated QR code
     *
     * @return int
     */
    public function getQrPadding(): int
    {
        return $this->qrPadding;
    }

    /**
     * Returns the string used to salt generated nonces
     *
     * @return string
     */
    public function getNonceSalt(): string
    {
        return $this->nonceSalt;
    }

    /**
     * Returns the string used as initialization vector for generated nonces
     *
     * @return string
     */
    public function getIv(): string
    {
        return $this->iv;
    }

    /**
     * Sets the versions this SQRL server supports
     *
     * @param mixed $acceptedVersions
     *
     */
    public function setAcceptedVersions($acceptedVersions)
    {
        if (is_array($acceptedVersions)) {
            $this->acceptedVersions = $acceptedVersions;
        } else {
            $this->acceptedVersions = [$acceptedVersions];
        }
    }

    /**
     * Sets whether responses to the server should be secure
     *
     * @param boolean $secure
     *
     */
    public function setSecure(bool $secure)
    {
        $this->secure = $secure;
    }

    /**
     * Sets the domain clients should generate a key for
     *
     * @param string $domain
     *
     */
    public function setDomain(string $domain)
    {
        $this->domain = $domain;
    }

    /**
     * Sets the path to the authentication script
     *
     * @param string $authenticationPath
     *
     */
    public function setAuthenticationPath(string $authenticationPath)
    {
        $this->authenticationPath = $authenticationPath;
    }

    /**
     * Sets whether users are allowed to generate anonymous accounts
     *
     * @param boolean $anonAllowed
     *
     */
    public function setAnonAllowed(bool $anonAllowed)
    {
        $this->anonAllowed = (bool)$anonAllowed;
    }

    /**
     * Sets the time in minutes that a nonce is considered valid
     *
     * @param int $nonceMaxAge
     *
     */
    public function setNonceMaxAge(int $nonceMaxAge)
    {
        $this->nonceMaxAge = $nonceMaxAge;
    }

    /**
     * Sets the height, in pixels, of a generated QR code
     *
     * @param int $qrHeight
     *
     */
    public function setQrHeight(int $qrHeight)
    {
        $this->qrHeight = $qrHeight;
    }

    /**
     * Sets the padding, in pixels, around a generated QR code
     *
     * @param int $qrPadding
     *
     */
    public function setQrPadding(int $qrPadding)
    {
        $this->qrPadding = $qrPadding;
    }

    /**
     * Sets the string used to salt generated nonces
     *
     * @param string $nonceSalt
     *
     */
    public function setNonceSalt(string $nonceSalt)
    {
        $this->nonceSalt = $nonceSalt;
    }

    /**
     * Sets the random string used as initialization vector for nonces
     *
     * @param string $nonceSalt
     *
     */
    public function setNonceIv(string $iv)
    {
        $this->iv = $iv;
    }

    /**
     * Validates a supplied signature against the original and the public key
     *
     * @param string $orig The original message
     * @param string $sig  The signature to verify
     * @param string $pk   The public key derived from the private key that created the signature
     *
     * @return boolean
     */
    public function validateSignature(string $orig, string $sig, string $pk): bool
    {
        $msg_orig = sodium_crypto_sign_open($sig.$orig, $pk);
        return $msg_orig !== false;
    }

    /**
     * Validates the returned server value
     *
     * @param string|array $server The returned server value
     * @param string $nut The nut from the request
     * @param bool $secure Whether the request was secure
     *
     * @return boolean
     */
    public function validateServer($server, string $nut, bool $secure): bool
    {
        if (is_string($server)) {
            return $server === $this->generateUrl($this->config, $nut) &&
                    $secure === $this->getSecure();
        } else {
            if (!isset($server['ver']) ||
                !isset($server['nut']) ||
                !isset($server['tif']) ||
                !isset($server['qry'])
            ) {
                return false;
            }
            $nutInfo = $this->getNutDetails($nut);
            return $server['ver'] === implode(',', $this->getAcceptedVersions()) &&
                    $server['nut'] === $nut &&
                    (!is_array($nutInfo) || hexdec($server['tif']) === $nutInfo['tif']) &&
                    $server['qry'] === $this->generateQry($this->getAuthenticationPath(), $nut) &&
                    $secure === $this->getSecure();
        }
    }

    /**
     * Validates a supplied nut
     *
     * @param string $nut
     * @param string $signingKey The key used to sign the current request
     *
     * @return int One of the nut class constants
     */
    public function validateNut(string $nut, string $signingKey = null): int
    {
        $nutInfo = $this->getNutDetails($nut);
        $maxAge = '-'.$this->getNonceMaxAge().' minutes';
        if (!is_array($nutInfo)) {
            return self::INVALID_NUT;
        } elseif ($nutInfo['createdDate']->format('U') < strtotime($maxAge)) {
            return self::EXPIRED_NUT;
        } elseif (!is_null($signingKey) &&
            !empty($nutInfo['originalKey']) &&
            $nutInfo['originalKey'] !== $signingKey
        ) {
            return self::KEY_MISMATCH;
        } else {
            return self::VALID_NUT;
        }
    }

    //Setup the logger
    protected function setupLogger()
    {

      // Set the logging level for logging to file
      // 0=none, 1=low, 2=medium, 3=verbose
      define("ERROR_LOG_LEVEL_FILE", 3);
      // Set the logging level to stdout
      // 0=none, 1=low, 2=medium, 3=verbose
      // SANDBOX_MODE will automatically set stdout errors to none
      define("ERROR_LOG_LEVEL_STDOUT", 0);
      // Apply config rules to error reporting; always set `on`
      error_reporting(-1); // -1 for reporting, 1 for none (Always set to -1)
      ini_set('display_errors', "On");
      ini_set('display_startup_errors', "On");
      // Set the error log file and turn on file-based error logging
      ini_set("log_errors", 1); // (Always set to `1` for logging)
      ini_set("error_log", $this->error_log);
      // Define the default exception handler
      // this allows exceptions to be directed to log file and stdout
      //set_exception_handler($this->exceptionHandler());
      // Define the default error handler and error handler funcitons
      // this allows errors to be directed to log file and stdout
      //set_error_handler($this->errorHandler());

    }

    // Define exception handler
    protected function exceptionHandler($exception){

      // TODO: find way to set $log_level depending on the E_USER_NOTICE, E_USER_WARNING, E_USER_ERROR
      // for now set $log_level to `EXCEPTION`
      $log_level = "Exception";
      try{
        echo "<b>Sqrl ".$log_level."</b>: " , $exception->getMessage()." in <b>".$exception->getFile()."</b> on line <b>".$exception->getLine()."</b><br><br>";
        error_log("[".date('Y-m-d H:i:s e')."] "."Sqrl ".$log_level.": ".$exception->getMessage()." in ".$exception->getFile()." on line ".$exception->getLine()."\n", 3, ERROR_LOG);
      }catch (Exception $e){
        echo "\nSqrl Logging Error: Check permissions of ".SQRL_PHP_DIRPATH."log/".ERROR_LOG , $exception->getMessage(), "\n\n";
      }
    }

    // Define the error handler
    protected function errorHandler($errno, $errstr, $errfile, $errline){

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
          echo "<b>Sqrl Error ".$log_level_string."</b>: ".$errstr." in <b>".$errfile."</b> on line <b>".$errline."</b><br><br>";
        }catch(Exception $e){
          echo "\nLogging Error: Check permissions of ".APP_ROOT_DIR."/".ERROR_LOG , $exception->getMessage(), "\n\n";
        }
      }


    }

    /**
     * Parses a user request
     *
     * This will determine what type of request is being performed and set values
     * up for use in validation and creating the response.
     *
     * @param array $get    The user's GET request
     * @param array $post   The user's POST body
     * @param array $server Server level variables (the _SERVER array)
     *
     * @throws \Exception
     * @throws SqrlException
     *
     * @return void
     */
    public function parseRequest($get, $post, $server)
    {
        //check that all the right pieces exist
        if (isset($post['client']) && isset($post['server']) && isset($post['ids']) && isset($get['nut'])) {
            $serverInfo = $this->parseServer($post['server']);
            $clientInfo = $this->parseClient($post['client']);
            $this->requestNut = $get['nut'];
            if (empty($serverInfo) || empty($clientInfo) || !isset($clientInfo['ver'])) {
                $this->tif|= (self::COMMAND_FAILED|self::CLIENT_FAILURE);
                return;
            }
            if (!$this->validateServer($serverInfo,$this->requestNut,isset($server['HTTPS'])?$server['HTTPS']:false)) {
                $this->tif|= (self::COMMAND_FAILED|self::CLIENT_FAILURE);
                return;
            }
            $nutStatus = $this->validateNut($this->requestNut,isset($clientInfo['idk'])?$clientInfo['idk']:null);
            if ($nutStatus !== \Sqrl\SqrlValidateInterface::VALID_NUT) {
                if ($nutStatus === \Sqrl\SqrlValidateInterface::EXPIRED_NUT) {
                    $this->authenticationKey = $clientInfo['idk'];
                    $this->tif|= (self::COMMAND_FAILED|self::TRANSIENT_ERROR);
                } elseif ($nutStatus === SqrlValidateInterface::KEY_MISMATCH) {
                    $this->tif|= (self::COMMAND_FAILED|self::CLIENT_FAILURE|self::BAD_ID_ASSOCIATION);
                } else {
                    $this->tif|= (self::COMMAND_FAILED|self::CLIENT_FAILURE);
                }
                return;
            } else {
                $this->tif|= $this->nutIPMatches($get['nut'],$server['REMOTE_ADDR'])?self::IP_MATCH:0;
            }
            if (!$this->validateSignatures($post, $clientInfo)) {
                $this->tif|= (self::COMMAND_FAILED|self::CLIENT_FAILURE);
                return;
            }
            $this->authenticationKey = $clientInfo['idk'];
            if (isset($clientInfo['vuk'])) {
                $this->clientSUK = isset($clientInfo['suk'])?$clientInfo['suk']:'';
                $this->clientVUK = $clientInfo['vuk'];
            }
            if (isset($clientInfo['pidk'])) {
                $this->previousIdKey = $clientInfo['pidk'];
            }
            $this->actions = $clientInfo['actions'];
            $this->clientOptions = isset($clientInfo['options'])?$clientInfo['options']:array();
            return;
        }
        $this->tif = (self::COMMAND_FAILED|self::CLIENT_FAILURE);
        return;
    }

    private function validateSignatures($post,$clientInfo)
    {
        if (!$this->validateSignature(
                $post['client'].$post['server'],
                $clientInfo['idk'],
                $this->base64URLDecode($post['ids'])
                )) {
            return false;
        }
        if (isset($post['urs']) && isset($clientInfo['vuk']) && !isset($clientInfo['pidk']) && !$this->validator->validateSignature(
                $post['client'].$post['server'],
                $clientInfo['vuk'],
                $this->base64URLDecode($post['urs'])
                )) {
            return false;
        }
        if (isset($post['urs']) && isset($clientInfo['vuk']) && isset($clientInfo['pidk']) && !$this->validator->validateSignature(
                $post['client'].$post['server'],
                $this->getIdentityVUK($clientInfo['pidk']),
                $this->base64URLDecode($post['urs'])
                )) {
            return false;
        }
        if (isset($post['pids']) && isset($clientInfo['pidk']) && !$this->validator->validateSignature(
                $post['client'].$post['server'],
                $clientInfo['pidk'],
                $this->base64URLDecode($post['pids'])
                )) {
            return false;
        }
        return true;
    }

    /**
     * Takes a (base64Url decoded) client value string and breaks it into its individual values
     * @param string $clientInput
     * @return void
     */
    protected function parseClient($clientInput)
    {
        $inputAsArray = explode("\n", $this->base64URLDecode($clientInput));
        $return = array();
        foreach (array_filter($inputAsArray) as $individualInputs) {
            if (strpos($individualInputs, '=') === false) {
                continue;
            }
            list($key,$val) = explode("=", $individualInputs);
            $val = trim($val);//strip off the \r
            switch (trim($key)){
                case 'ver':
                    $return['ver']=$val;
                    break;
                case 'cmd':
                    $return['actions'] = explode('~',$val);
                    break;
                case 'idk':
                    $return['idk']=$this->base64URLDecode($val);
                    break;
                case 'pidk':
                    $return['pidk']=$this->base64URLDecode($val);
                    break;
                case 'vuk':
                    $return['vuk']=$this->base64URLDecode($val);
                    break;
                case 'suk':
                    $return['suk']=$this->base64URLDecode($val);
                    break;
                case 'opt':
                    $return['options'] = explode('~',$val);
                    break;
            }
        }
        return $return;
    }

    protected function parseServer($serverData)
    {
        $decoded = $this->base64URLDecode($serverData);
        if (substr($decoded,0,7)==='sqrl://' || substr($decoded,0,6)==='qrl://'){
            return $decoded;
        } else {
            $serverValues = explode("\r\n", $decoded);
            $parsedResult = array();
            foreach ($serverValues as $value) {
                $splitStop = strpos($value, '=');
                $key = substr($value, 0, $splitStop);
                $val = substr($value, $splitStop+1);
                $parsedResult[$key]=$val;
            }
            return $parsedResult;
        }
    }

    /**
     * Gets the text message to be returned to the SQRL client
     *
     * @throws \Exception
     * @throws SqrlException
     * @return string
     */
    public function getResponseMessage()
    {
        foreach ($this->actions as $action) {
            if ($this->tif&self::COMMAND_FAILED) {
                break;
            }
            $this->$action();
        }
        return $this->formatResponse($this->tif);
    }

    protected function query()
    {
        $identityStatus = $this->checkIdentityKey($this->authenticationKey);
        if ($identityStatus === SqrlStoreInterface::IDENTITY_ACTIVE) {
            $this->tif|= self::ID_MATCH;
        } elseif (!empty($this->previousIdKey)) {
            if ($this->checkIdentityKey($this->previousIdKey) === SqrlStoreInterface::IDENTITY_ACTIVE) {
                $this->tif|= self::PREVIOUS_ID_MATCH;
            }
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_UNKNOWN) {
            if (!$this->getAnonAllowed()) {//notify the client that anonymous authentication is not allowed in this transaction
                $this->tif|= self::FUNCTION_NOT_SUPPORTED|self::COMMAND_FAILED;
            }
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_LOCKED) {
            $this->tif|= self::ID_MATCH|self::SQRL_DISABLED;
        }
    }

    protected function ident()
    {
        $identityStatus = $this->checkIdentityKey($this->authenticationKey);
        if ($identityStatus === SqrlStoreInterface::IDENTITY_ACTIVE) {
            $this->logSessionIn($this->requestNut);
            $this->tif|= self::ID_MATCH;
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_UNKNOWN) {
            $this->identUnknownIdentity();
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_LOCKED) {
            if (empty($this->clientSUK) || $this->clientVUK !== $this->getIdentityVUK($this->authenticationKey)) {
                $this->tif|= (self::CLIENT_FAILURE|self::COMMAND_FAILED);
            } else {
                $this->unlockIdentityKey($this->authenticationKey);
                $this->logSessionIn($this->requestNut);
                $this->tif|= self::ID_MATCH;
            }
        }
    }

    private function identUnknownIdentity()
    {
        if (!empty($this->previousIdKey) &&
                $this->checkIdentityKey($this->previousIdKey) !== SqrlStoreInterface::IDENTITY_UNKNOWN) {
            if (empty($this->clientSUK) || empty($this->clientVUK)) {
                $this->tif|= (self::CLIENT_FAILURE|self::COMMAND_FAILED);
            } else {
                $this->updateIdentityKey($this->previousIdKey,$this->authenticationKey,$this->clientSUK,$this->clientVUK);
                $this->logSessionIn($this->requestNut);
                $this->tif|= self::ID_MATCH|self::PREVIOUS_ID_MATCH;
            }
            return;
        }
        if (!$this->getAnonAllowed()) {//notify the client that anonymous authentication is not allowed in this transaction
            $this->tif|= (self::FUNCTION_NOT_SUPPORTED|self::COMMAND_FAILED);
        } elseif (empty($this->clientSUK)) {
            $this->tif|= (self::CLIENT_FAILURE|self::COMMAND_FAILED);
        } else {
            $this->createIdentity($this->authenticationKey,$this->clientSUK,$this->clientVUK);
            $this->logSessionIn($this->requestNut);
            $this->tif|= self::ID_MATCH;
        }
    }

    protected function lock()
    {
        $identityStatus = $this->checkIdentityKey($this->authenticationKey);
        if ($identityStatus !== SqrlStoreInterface::IDENTITY_UNKNOWN) {
            $this->lockIdentityKey($this->authenticationKey);
            $this->endSession($this->requestNut);
            $this->tif|= (self::ID_MATCH|self::SQRL_DISABLED);
        } else {
            $this->tif|= (self::COMMAND_FAILED|self::CLIENT_FAILURE);
        }
    }

    /**
     * Gets the numeric HTTP code to return to the SQRL client
     *
     * Currently the spec only uses the 200 code and any error message is in the
     * test message response
     *
     * @return int
     */
    public function getResponseCode()
    {
        return $this->responseCode;
    }

    /**
     * A helper function to send the response message and code to the SQRL client
     *
     * @return void
     */
    public function sendResponse()
    {
        echo $this->getResponseMessage();
    }

    /**
     * Formats a response to send back to a client
     *
     * @param int $code The TIF code to send back to the client
     *
     * @return string
     */
    protected function formatResponse($code)
    {
        $resp = 'ver='.implode(',',$this->getAcceptedVersions())."\r\n"
                ."nut=".$this->sqrlGenerator->getNonce($code, $this->authenticationKey, $this->requestNut)."\r\n"
                .'tif='.  strtoupper(dechex($code))."\r\n"
                ."qry=".$this->sqrlGenerator->generateQry();
        if (!empty($this->ask)) {
            $resp.= "\r\nask=".$this->ask;
        }
        if (($this->tif&self::SQRL_DISABLED && !in_array('lock', $this->actions))) {
            $resp.= "\r\nsuk=".$this->base64UrlEncode($this->getIdentitySUK($this->authenticationKey));
        } elseif ($this->tif&self::PREVIOUS_ID_MATCH && !in_array('ident', $this->actions)) {
            $resp.= "\r\nsuk=".$this->base64UrlEncode($this->getIdentitySUK($this->previousIdKey));
        }
        return $this->base64UrlEncode($resp);
    }

    // Connect to the database
    protected function databaseConnect()
    {
      if($this->conn instanceof PDO){
          $this->db_status = true;
      }else{

        try{
            $this->conn = new \PDO($this->db_application.':host='. $this->db_host .';dbname='. $this->db_name . ';charset=utf8', $this->db_username, $this->db_password);
            $this->db_status = true;
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        }catch (PDOException $e){
            trigger_error("Database Connection Error: ".$e->getMessage(), E_USER_ERROR);
            $this->user_db_status = false;
            return false;
        }
      }
    }

    //stores a sqrl set of login data (nut, )
    public function storeIssuedNutRecord(string $nut, string $ip, string $session_id): bool
    {

        try{

            $query = $this->conn->prepare('
            INSERT INTO sqrl_login.`sqrl_nuts`
            (nut, ip, session_id)
            VALUES(:nut, :ip, :session_id)
            ');
            $query->bindValue(':nut', $nut, PDO::PARAM_STR);
            $query->bindValue(':ip', $ip, PDO::PARAM_STR);
            $query->bindValue(':session_id', $session_id, PDO::PARAM_STR);
            $query->execute();

            return true;

        }catch(PDOException $e){

            trigger_error("SQRL storeIssuedNutRecord Failed: Database Error - ".$query->errorInfo()[0]." ".$query->errorInfo()[1]." ".$query->errorInfo()[2], E_USER_WARNING);
            trigger_error($e);

            return false;

        }

    }

    //clear database of expired nuts
    public function clearExpiredNuts(): bool
    {
      try{

          $query = $this->conn->prepare('
          DELETE FROM sqrl_login.`sqrl_nuts`
          WHERE created < (NOW() - INTERVAL 48 HOUR)
          ');
          $query->execute();

          return true;

      }catch(PDOException $e){

          trigger_error("SQRL clearExpiredNuts Failed: Database Error - ".$query->errorInfo()[0]." ".$query->errorInfo()[1]." ".$query->errorInfo()[2], E_USER_WARNING);
          trigger_error($e);

          return false;

      }
    }

    //delete a nut record that has been validated
    public function deleteValidatedNut(string $nut, string $ip): bool
    {

      try{

          $query = $this->conn->prepare('
          DELETE FROM sqrl_login.`sqrl_nuts`
          WHERE nut=:nut
          AND ip=:ip
          ');
          $query->bindValue(':nut', $nut, PDO::PARAM_STR);
          $query->bindValue(':ip', $ip, PDO::PARAM_STR);
          $query->execute();

          return true;

      }catch(PDOException $e){

          trigger_error("SQRL deleteValidatedNut Failed: Database Error - ".$query->errorInfo()[0]." ".$query->errorInfo()[1]." ".$query->errorInfo()[2], E_USER_WARNING);
          trigger_error($e);

          return false;

      }

    }

    //store a new user public key as user id
    public function storeNewPublicKey($public_key): bool
    {


    }

    public function getNutRecordToValidate($nut): array
    {

      try{

          $query = $this->conn->prepare('
          SELECT nut, create, ip
          FROM  sqrl_login.`sqrl_nuts`
          WHERE nut=:nut
          AND verified = 0
          ');
          $query->bindValue(':nut', $nut, PDO::PARAM_STR);
          $query->execute();

      }catch(PDOException $e){

          trigger_error("Sqrl getNutRecordToValidate failed: Database Error - ".$query->errorInfo()[0]." ".$query->errorInfo()[1]." ".$query->errorInfo()[2], E_USER_WARNING);
          trigger_error($e);


      }

    }

    public function storeValidatedStatus($nut): bool
    {

    }

    //santize the incoming request from an Sqrl client
    public function sanitizeClientRequest()
    {
      $this->santizeGetData();
      $this->sanitizePostData();
      $this->sanitizeServerData();
    }

    //sanitize $_GET
    protected function santizeGetData()
    {

    }

    //santize $_POST
    protected function sanitizePostData()
    {

    }

    //sanitize $_SERVER
    protected function sanitizeServerData()
    {

    }

}
