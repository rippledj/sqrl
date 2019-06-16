<?php
declare(strict_types=1);
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
 * Validates a nonce/public key pair
 *
 * If a database is configured, this will also check to see if the public key
 * matches a previously encountered key. If it does it will load an identifier.
 * If there is no match, it will store the public key and generate an identifier.
 */
class SqrlValidate
{
    /**
     * @var SqrlDatabase
     */
    protected $database = null;

    /**
     *
     * @var SqrlConfiguration
     */
    protected $configuration = null;

    /**
     *
     * @param \Sqrl\SqrlConfiguration $config
     * @param \Sqrl\SqrlDatabase $storage
     */
    public function __construct(
        SqrlConfiguration $config,
        SqrlDatabase $database
    ) {
        $this->config = $config;
        $this->database = $database;
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
                    $secure === $this->config->getSecure();
        } else {
            if (!isset($server['ver']) ||
                !isset($server['nut']) ||
                !isset($server['tif']) ||
                !isset($server['qry'])
            ) {
                return false;
            }
            $nutInfo = $this->store->getNutDetails($nut);
            return $server['ver'] === implode(',', $this->config->getAcceptedVersions()) &&
                    $server['nut'] === $nut &&
                    (!is_array($nutInfo) || hexdec($server['tif']) === $nutInfo['tif']) &&
                    $server['qry'] === $this->generateQry($this->config->getAuthenticationPath(), $nut) &&
                    $secure === $this->config->getSecure();
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
        $nutInfo = $this->store->getNutDetails($nut);
        $maxAge = '-'.$this->config->getNonceMaxAge().' minutes';
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


}
