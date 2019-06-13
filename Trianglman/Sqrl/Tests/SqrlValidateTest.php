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
namespace Trianglman\Sqrl\Tests;

use PHPUnit\Framework\MockObject\MockObject;
use Trianglman\Sqrl\NonceValidatorInterface;
use Trianglman\Sqrl\SqrlConfiguration;
use Trianglman\Sqrl\SqrlStoreInterface;
use Trianglman\Sqrl\SqrlValidate;
use PHPUnit\Framework\TestCase;
use Trianglman\Sqrl\SqrlValidateInterface;
use Trianglman\Sqrl\Traits\Base64Url;

/**
 * Unit tests for the SqrlValidate class
 *
 * @author johnj
 */
class SqrlValidateTest extends TestCase
{
    use Base64Url;
    /**
     * @var MockObject|SqrlConfiguration
     */
    protected $config = null;
    /**
     * @var MockObject|NonceValidatorInterface
     */
    protected $val = null;
    /**
     * @var MockObject|SqrlStoreInterface
     */
    protected $storage = null;
    /**
     * @var SqrlValidate
     */
    protected $obj = null;
    
    public function setup()
    {
        $this->config = $this->getMockBuilder(SqrlConfiguration::class)->getMock();
        $this->val = $this->getMockBuilder(NonceValidatorInterface::class)->getMock();
        $this->storage = $this->getMockBuilder(SqrlStoreInterface::class)->getMock();
        
        $this->obj = new SqrlValidate($this->config,$this->val,$this->storage);
    }
    
    public function testValidatesServerFromUrl()
    {
        $this->config->expects($this->any())->method('getDomain')
            ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        
        $this->assertTrue($this->obj->validateServer('sqrl://example.com/sqrl?nut=1234', '1234', true));
    }
    
    public function testValidatesServerFromUrlWithExtendedDomain()
    {
        $this->config->expects($this->any())->method('getDomain')
            ->will($this->returnValue('example.com/~user'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/~user/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        
        $this->assertTrue($this->obj->validateServer('sqrl://example.com/~user/sqrl?nut=1234&x=6', '1234', true));
    }
    
    public function testValidatesServerFromUrlInvalidSecurity()
    {
        $this->config->expects($this->any())->method('getDomain')
            ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        
        
        $this->assertFalse($this->obj->validateServer('sqrl://example.com/sqrl?nut=1234', '1234', false));
    }
    
    public function testValidatesServerFromUrlInvalidProtocol()
    {
        $this->config->expects($this->any())->method('getDomain')
            ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        
        $this->assertFalse($this->obj->validateServer('qrl://example.com/sqrl?nut=1234', '1234', true));
    }
    
    public function testValidatesServerFromUrlInvalidDomain()
    {
        $this->config->expects($this->any())->method('getDomain')
            ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        
        $this->assertFalse($this->obj->validateServer('sqrl://fakeexample.com/sqrl?nut=1234', '1234', true));
    }
    
    public function testValidatesServerFromUrlInvalidAuthPath()
    {
        $this->config->expects($this->any())->method('getDomain')
            ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        
        $this->assertFalse($this->obj->validateServer('sqrl://example.com/notsqrl?nut=1234', '1234', true));
    }
    
    public function testValidatesServerFromUrlNutDoesntMatch()
    {
        $this->config->expects($this->any())->method('getDomain')
            ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        
        $this->assertFalse($this->obj->validateServer('sqrl://example.com/sqrl?nut=1234', '1235', true));
    }
    
    public function testValidatesServerFromArray()
    {
        $this->config->expects($this->any())->method('getAcceptedVersions')
            ->will($this->returnValue([1]));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('newNut'))
            ->will($this->returnValue([
                'tif' => 0xD,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        
        $server = [
            'ver' => '1',
            'nut' => 'newNut',
            'tif' => 'D',
            'qry' => '/sqrl?nut=newNut',
            'suk' => $this->base64UrlEncode('validSUK')
        ];
        $this->assertTrue($this->obj->validateServer($server, 'newNut', true));
    }
    
    public function testValidatesServerFromArrayMissingRequiredFields()
    {
        $server = [
            'ver' => '1',
            'nut' => 'newNut',
            'qry' => '/sqrl?nut=newNut',
            'suk' => $this->base64UrlEncode('validSUK')
        ];
        $this->assertFalse($this->obj->validateServer($server, 'newNut', true));
    }
    
    public function testValidatesServerFromArrayInvalidVersion()
    {
        $this->config->expects($this->any())->method('getAcceptedVersions')
            ->will($this->returnValue([1]));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('newNut'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        
        $server = [
            'ver' => '666',
            'nut' => 'newNut',
            'tif' => '5',
            'qry' => '/sqrl?nut=newNut',
            'suk' => $this->base64UrlEncode('validSUK')
        ];
        $this->assertFalse($this->obj->validateServer($server, 'newNut', true));
    }
    
    public function testValidatesServerFromArrayInvalidTif()
    {
        $this->config->expects($this->any())->method('getAcceptedVersions')
            ->will($this->returnValue([1]));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('newNut'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));

        $server = [
            'ver' => '666',
            'nut' => 'newNut',
            'tif' => '20',
            'qry' => '/sqrl?nut=newNut',
            'suk' => $this->base64UrlEncode('validSUK')
        ];
        $this->assertFalse($this->obj->validateServer($server, 'newNut', true));
    }
    
    public function testValidatesServerFromArrayInvalidQry()
    {
        $this->config->expects($this->any())->method('getAcceptedVersions')
            ->will($this->returnValue([1]));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('newNut'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));

        $server = [
            'ver' => '1',
            'nut' => 'newNut',
            'tif' => '5',
            'qry' => '/notsqrl?nut=newNut',
            'suk' => $this->base64UrlEncode('validSUK')
        ];
        $this->assertFalse($this->obj->validateServer($server, 'newNut', true));
    }

    public function testValidatesServerFromArraySecurityDowngrade()
    {
        $this->config->expects($this->any())->method('getAcceptedVersions')
            ->will($this->returnValue([1]));
        $this->config->expects($this->any())->method('getAuthenticationPath')
            ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
            ->will($this->returnValue(true));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('newNut'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        
        $server = [
            'ver' => '1',
            'nut' => 'newNut',
            'tif' => '5',
            'qry' => '/sqrl?nut=newNut',
            'suk' => $this->base64UrlEncode('validSUK')
        ];
        $this->assertFalse($this->obj->validateServer($server, 'newNut', false));
    }
    
    public function testValidatesGoodNut()
    {
        $this->config->expects($this->any())->method('getNonceMaxAge')
            ->will($this->returnValue(5));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('1234'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        $this->assertEquals(SqrlValidateInterface::VALID_NUT, $this->obj->validateNut('1234'));
    }
    
    public function testValidatesExpiredNut()
    {
        $this->config->expects($this->any())->method('getNonceMaxAge')
            ->will($this->returnValue(5));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('old1234'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime('-6 minutes'),
                'nutIP' => '192.168.0.105'
            ]));
        $this->assertEquals(SqrlValidateInterface::EXPIRED_NUT, $this->obj->validateNut('old1234'));
    }
    
    public function testValidatesUnknownNut()
    {
        $this->config->expects($this->any())->method('getNonceMaxAge')
            ->will($this->returnValue(5));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('you know nothing'))
            ->will($this->returnValue(null));
        $this->assertEquals(SqrlValidateInterface::INVALID_NUT, $this->obj->validateNut('you know nothing'));
    }
    
    public function testValidatesGoodNutMatchingKey()
    {
        $this->config->expects($this->any())->method('getNonceMaxAge')
            ->will($this->returnValue(5));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('1234'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        $this->assertEquals(SqrlValidateInterface::VALID_NUT, $this->obj->validateNut('1234','some key'));
    }
    
    public function testValidatesGoodNutMismatchKey()
    {
        $this->config->expects($this->any())->method('getNonceMaxAge')
            ->will($this->returnValue(5));
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('1234'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        $this->assertEquals(SqrlValidateInterface::KEY_MISMATCH, $this->obj->validateNut('1234','different key'));
    }
    
    public function testValidatesSignature()
    {
        $this->val->expects($this->any())->method('validateSignature')
            ->with(
                $this->equalTo('original message'),
                $this->equalTo('signature'),
                $this->equalTo('good key')
            )->will($this->returnValue(true));
        
        $this->assertTrue($this->obj->validateSignature('original message', 'good key', 'signature'));
    }
    
    public function testValidatesBadSignature()
    {
        $this->val->expects($this->any())->method('validateSignature')
            ->with(
                $this->equalTo('original message'),
                $this->equalTo('bad signature'),
                $this->equalTo('some key')
            )->will($this->returnValue(false));
        
        
        $this->assertFalse($this->obj->validateSignature('original message', 'some key', 'bad signature'));
    }
    
    public function testChecksNutIPMatch()
    {
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('anut'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        
        $this->assertTrue($this->obj->nutIPMatches('anut', '192.168.0.105'));
    }
    
    public function testChecksNutIPMismatch()
    {
        $this->storage->expects($this->any())->method('getNutDetails')
            ->with($this->equalTo('anut'))
            ->will($this->returnValue([
                'tif' => 0x5,
                'originalKey' => 'some key',
                'originalNut' => 'someNut',
                'createdDate' => new \DateTime(),
                'nutIP' => '192.168.0.105'
            ]));
        
        $this->assertFalse($this->obj->nutIPMatches('anut', '127.0.0.1'));
    }
}
