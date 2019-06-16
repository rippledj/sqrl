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

/**
 * Generates a SQRL QR image, URL and nonce.
 */
class SqrlGenerate
{
    /**
     * @const
     * @var int
     */
    const NUT_STRENGTH = 128;

    /**
     * @var string
     */
    protected $nonce = '';

    /**
     * @var SqrlConfiguration
     */
    protected $config = null;

    public function __construct(SqrlConfiguration $config, SqrlDatabase $database)
    {
        $this->database = $database;
        $this->config = $config;
    }

    public function getUrl(): string
    {
        return $this->generateUrl($this->generateNut());
    }

    public function render(?string $outputFile = null)
    {
        $qrCode = new QrCode();
        $qrCode->setText($this->getUrl());
        $qrCode->setSize($this->config->getQrHeight());
        $qrCode->setPadding($this->config->getQrPadding());
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
         $this->nonce = substr(md5(uniqid('', true)), 0, 12);
         return $this->nonce;
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
        if($this->config->getSecure() > 0 || $_SERVER['HTTPS']) $url = 'sqrl://';
        else $url = 'qrl://';
        //build the base Sqrl url
        $url .= $this->config->getDomain().$this->config->getAuthenticationPath().'?nut='.$nut;
        //calculate the extention onto the base domain (x value)
        if (strpos($this->config->getDomain(), '/') !== false) {
            $path_extension = strlen($this->config->getDomain())-strpos($this->config->getDomain(), '/');
            $url .= '&x='.$path_extension;
        }
        //attach the server friendly name
        //$url .= '&sfn='.$this->base64UrlEncode($this->config->getFriendlyName());

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
        return $this->nonce;
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

}
