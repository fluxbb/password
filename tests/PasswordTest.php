<?php
/**
 * FluxBB
 *
 * LICENSE
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * @category	FluxBB
 * @package		Flux_Password
 * @subpackage	Tests
 * @copyright	Copyright (c) 2011 FluxBB (http://fluxbb.org)
 * @license		http://www.gnu.org/licenses/lgpl.html	GNU Lesser General Public License
 */

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
