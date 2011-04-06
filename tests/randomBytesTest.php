<?php

require_once dirname(__FILE__).'/../password.php';

class RandomBytesTest extends PHPUnit_Framework_TestCase
{
	public function testDataLength()
	{
		// Raw data should be the same length as requested
		$data = PasswordHash::random_bytes(20, true);
		$this->assertEquals(strlen($data), 20);

		// Hex data should be 2x the requested length
		$data = PasswordHash::random_bytes(20, false);
		$this->assertEquals(strlen($data), 40);
	}

	public function testNotEqual()
	{
		$r1 = PasswordHash::random_bytes(20);
		$r2 = PasswordHash::random_bytes(20);

		$this->assertNotEquals($r1, $r2);
	}
}
