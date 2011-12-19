<?php

require_once dirname(__FILE__).'/../src/Password.php';

class Flux_PasswordTest extends PHPUnit_Framework_TestCase
{
	public function testHashValidate()
	{
		$hash = Flux_Password::hash('hello world');

		$this->assertTrue(Flux_Password::validate('hello world', $hash));
		$this->assertFalse(Flux_Password::validate('goodbye world', $hash));
	}
	
	public function testRandomBytesDataLength()
	{
		// Raw data should be the same length as requested
		$data = Flux_Password::randomBytes(20, true);
		$this->assertEquals(strlen($data), 20);
	
		// Hex data should be 2x the requested length
		$data = Flux_Password::randomBytes(20, false);
		$this->assertEquals(strlen($data), 40);
	}
	
	public function testRandomBytesNotEqual()
	{
		$r1 = Flux_Password::randomBytes(20);
		$r2 = Flux_Password::randomBytes(20);
	
		$this->assertNotEquals($r1, $r2);
	}
	
	public function testRandomKeyDataLength()
	{
		// A key should be the same length as requested
		$key = Flux_Password::randomKey(20);
		$this->assertEquals(strlen($key), 20);
	}
	
	public function testRandomKeyNotEqual()
	{
		$r1 = Flux_Password::randomKey(20);
		$r2 = Flux_Password::randomKey(20);
	
		$this->assertNotEquals($r1, $r2);
	}
}
