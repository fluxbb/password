<?php

require_once dirname(__FILE__).'/../src/Password.php';

class RandomKeyTest extends PHPUnit_Framework_TestCase
{
	public function testDataLength()
	{
		// A key should be the same length as requested
		$key = Flux_Password::randomKey(20);
		$this->assertEquals(strlen($key), 20);
	}

	public function testNotEqual()
	{
		$r1 = Flux_Password::randomKey(20);
		$r2 = Flux_Password::randomKey(20);

		$this->assertNotEquals($r1, $r2);
	}
}
