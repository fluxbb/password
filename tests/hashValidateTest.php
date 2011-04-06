<?php

require_once dirname(__FILE__).'/../password.php';

class HashValidateTest extends PHPUnit_Framework_TestCase
{
	public function testHashValidate()
	{
		$hash = PasswordHash::hash('hello world');

		$this->assertTrue(PasswordHash::validate('hello world', $hash));
		$this->assertFalse(PasswordHash::validate('goodbye world', $hash));
	}
}
