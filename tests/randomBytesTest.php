<?php

require_once dirname(__FILE__).'/../src/Password.php';

class RandomBytesTest extends PHPUnit_Framework_TestCase
{
	public function testDataLength()
	{
		// Raw data should be the same length as requested
		$data = Flux_Password::randomBytes(20, true);
		$this->assertEquals(strlen($data), 20);

		// Hex data should be 2x the requested length
		$data = Flux_Password::randomBytes(20, false);
		$this->assertEquals(strlen($data), 40);
	}

	public function testNotEqual()
	{
		$r1 = Flux_Password::randomBytes(20);
		$r2 = Flux_Password::randomBytes(20);

		$this->assertNotEquals($r1, $r2);
	}
}
