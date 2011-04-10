<?php

require_once dirname(__FILE__).'/../password.php';

class RandomKeyTest extends PHPUnit_Framework_TestCase
{
	public function testDataLength()
	{
		// A key should be the same length as requested
		$key = PasswordHash::random_key(20);
		$this->assertEquals(strlen($key), 20);
	}

	public function testNotEqual()
	{
		$r1 = PasswordHash::random_key(20);
		$r2 = PasswordHash::random_key(20);

		$this->assertNotEquals($r1, $r2);
	}
}
