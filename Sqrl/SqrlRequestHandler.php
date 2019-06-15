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

/**
 * A handler to process the authentication of SQRL clients
 *
 * This class will process a request, send it to the validator, then depending on
 * the type of request, send a success message, send an error message, or send a
 * request for more information (e.g. initiate the second loop to create a new user)
 *
 * @author johnj
 */
class SqrlRequestHandler
{
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

    /**
     * @var SqrlValidateInterface
     */
    protected $validator = null;

    /**
     * @var SqrlGenerateInterface
     */
    protected $sqrlGenerator = null;

    /**
     *
     * @var SqrlConfiguration
     */
    protected $config = null;

    /**
     *
     * @var SqrlStoreInterface
     */
    protected $store = null;

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

    public function __construct(
        SqrlConfiguration $config,
        SqrlValidateInterface $val,
        SqrlStoreDatabase $store = null,
        SqrlGenerateInterface $gen = null
    ) {
        $this->config = $config;
        $this->validator = $val;
        $this->sqrlGenerator = $gen;
        $this->store = $store;
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
            if (!$this->validator->validateServer($serverInfo,$this->requestNut,isset($server['HTTPS'])?$server['HTTPS']:false)) {
                $this->tif|= (self::COMMAND_FAILED|self::CLIENT_FAILURE);
                return;
            }
            $nutStatus = $this->validator->validateNut($this->requestNut,isset($clientInfo['idk'])?$clientInfo['idk']:null);
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
                $this->tif|= $this->validator->nutIPMatches($get['nut'],$server['REMOTE_ADDR'])?self::IP_MATCH:0;
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
        if (!$this->validator->validateSignature(
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
                $this->store->getIdentityVUK($clientInfo['pidk']),
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
        $identityStatus = $this->store->checkIdentityKey($this->authenticationKey);
        if ($identityStatus === SqrlStoreInterface::IDENTITY_ACTIVE) {
            $this->tif|= self::ID_MATCH;
        } elseif (!empty($this->previousIdKey)) {
            if ($this->store->checkIdentityKey($this->previousIdKey) === SqrlStoreInterface::IDENTITY_ACTIVE) {
                $this->tif|= self::PREVIOUS_ID_MATCH;
            }
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_UNKNOWN) {
            if (!$this->config->getAnonAllowed()) {//notify the client that anonymous authentication is not allowed in this transaction
                $this->tif|= self::FUNCTION_NOT_SUPPORTED|self::COMMAND_FAILED;
            }
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_LOCKED) {
            $this->tif|= self::ID_MATCH|self::SQRL_DISABLED;
        }
    }

    protected function ident()
    {
        $identityStatus = $this->store->checkIdentityKey($this->authenticationKey);
        if ($identityStatus === SqrlStoreInterface::IDENTITY_ACTIVE) {
            $this->store->logSessionIn($this->requestNut);
            $this->tif|= self::ID_MATCH;
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_UNKNOWN) {
            $this->identUnknownIdentity();
        } elseif ($identityStatus === SqrlStoreInterface::IDENTITY_LOCKED) {
            if (empty($this->clientSUK) || $this->clientVUK !== $this->store->getIdentityVUK($this->authenticationKey)) {
                $this->tif|= (self::CLIENT_FAILURE|self::COMMAND_FAILED);
            } else {
                $this->store->unlockIdentityKey($this->authenticationKey);
                $this->store->logSessionIn($this->requestNut);
                $this->tif|= self::ID_MATCH;
            }
        }
    }

    private function identUnknownIdentity()
    {
        if (!empty($this->previousIdKey) &&
                $this->store->checkIdentityKey($this->previousIdKey) !== SqrlStoreInterface::IDENTITY_UNKNOWN) {
            if (empty($this->clientSUK) || empty($this->clientVUK)) {
                $this->tif|= (self::CLIENT_FAILURE|self::COMMAND_FAILED);
            } else {
                $this->store->updateIdentityKey($this->previousIdKey,$this->authenticationKey,$this->clientSUK,$this->clientVUK);
                $this->store->logSessionIn($this->requestNut);
                $this->tif|= self::ID_MATCH|self::PREVIOUS_ID_MATCH;
            }
            return;
        }
        if (!$this->config->getAnonAllowed()) {//notify the client that anonymous authentication is not allowed in this transaction
            $this->tif|= (self::FUNCTION_NOT_SUPPORTED|self::COMMAND_FAILED);
        } elseif (empty($this->clientSUK)) {
            $this->tif|= (self::CLIENT_FAILURE|self::COMMAND_FAILED);
        } else {
            $this->store->createIdentity($this->authenticationKey,$this->clientSUK,$this->clientVUK);
            $this->store->logSessionIn($this->requestNut);
            $this->tif|= self::ID_MATCH;
        }
    }

    protected function lock()
    {
        $identityStatus = $this->store->checkIdentityKey($this->authenticationKey);
        if ($identityStatus !== SqrlStoreInterface::IDENTITY_UNKNOWN) {
            $this->store->lockIdentityKey($this->authenticationKey);
            $this->store->endSession($this->requestNut);
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
     * @param int $code The TIF code to send back to the user
     *
     * @return string
     */
    protected function formatResponse($code)
    {
        $resp = 'ver='.implode(',',$this->config->getAcceptedVersions())."\r\n"
                ."nut=".$this->sqrlGenerator->getNonce($code, $this->authenticationKey, $this->requestNut)."\r\n"
                .'tif='.  strtoupper(dechex($code))."\r\n"
                ."qry=".$this->sqrlGenerator->generateQry();
        if (!empty($this->ask)) {
            $resp.= "\r\nask=".$this->ask;
        }
        if (($this->tif&self::SQRL_DISABLED && !in_array('lock', $this->actions))) {
            $resp.= "\r\nsuk=".$this->base64UrlEncode($this->store->getIdentitySUK($this->authenticationKey));
        } elseif ($this->tif&self::PREVIOUS_ID_MATCH && !in_array('ident', $this->actions)) {
            $resp.= "\r\nsuk=".$this->base64UrlEncode($this->store->getIdentitySUK($this->previousIdKey));
        }
        return $this->base64UrlEncode($resp);
    }

    /**
     * Base 64 URL encodes a string
     *
     * Basically the same as base64 encoding, but replacing "+" with "-" and
     * "/" with "_" to make it safe to include in a URL
     *
     * Optionally removes trailing "=" padding characters.
     *
     * @param string $string The string to encode
     * @param type $stripEquals [Optional] Whether to strip the "=" off of the end
     *
     * @return string
     */
    protected function base64UrlEncode($string, $stripEquals=true)
    {
        $base64 = base64_encode($string);
        $urlencode = str_replace(array('+','/'), array('-','_'), $base64);
        if($stripEquals){
            $urlencode = trim($urlencode, '=');
        }
        return $urlencode;
    }

    /**
     * Base 64 URL decodes a string
     *
     * Basically the same as base64 decoding, but replacing URL safe "-" with "+"
     * and "_" with "/". Automatically detects if the trailing "=" padding has
     * been removed.
     *
     * @param type $string
     * @return type
     */
    protected function base64URLDecode($string)
    {
        $len = strlen($string);
        if($len%4 > 0){
            $string = str_pad($string, 4-($len%4), '=');
        }
        $base64 = str_replace(array('-','_'), array('+','/'), $string);
        return base64_decode($base64);
    }
}
