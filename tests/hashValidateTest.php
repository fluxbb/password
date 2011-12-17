<?php

require_once dirname(__FILE__).'/../src/Password.php';

class HashValidateTest extends PHPUnit_Framework_TestCase
{
	public function testHashValidate()
	{
		$hash = Flux_Password::hash('hello world');

		$this->assertTrue(Flux_Password::validate('hello world', $hash));
		$this->assertFalse(Flux_Password::validate('goodbye world', $hash));
	}
}
