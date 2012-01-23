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
 * @package		Password
 * @copyright	Copyright (c) 2011 FluxBB (http://fluxbb.org)
 * @license		http://www.gnu.org/licenses/lgpl.html	GNU Lesser General Public License
 */

namespace fluxbb\password;

/**
 * Fetches random data from a secure source if possible -
 * /dev/urandom on UNIX systems. Falls back to mt_rand()
 * if no better source is available.
 *
 * @param string $length
 * 		Number of bytes of random data to generate.
 *
 * @param bool $raw_output
 * 		When set to TRUE, the data is returned in raw
 * 		binary form, otherwise the returned value is a
 * 		($length * 2)-character hexadecimal number.
 *
 * @return string
 * 		The random data.
 */
function randomBytes($length, $raw_output = false)
{
	if (function_exists('openssl_random_pseudo_bytes'))
	{
		$data = openssl_random_pseudo_bytes($length);
	}
	else
	{
		$data = '';

		// On a UNIX system use /dev/urandom
		if (is_readable('/dev/urandom'))
		{
			$handle = @fopen('/dev/urandom', 'rb');
			if ($handle !== false)
			{
				$data = fread($handle, $length);
				fclose($handle);
			}
		}

		// Fall back to using md_rand() - not cryptographically secure, but available everywhere
		while (strlen($data) < $length)
		{
			$data .= pack('i', mt_rand());
		}

		if (strlen($data) > $length)
		{
			$data = substr($data, 0, $length);
		}
	}

	// If requested return the raw output
	if ($raw_output)
	{
		return $data;
	}

	// Otherwise return the data as a hex string
	return bin2hex($data);
}

/**
 * Generates a random key using the alphabet ./0-9A-Za-z.
 *
 * @param string $length
 * 		Length of the string to generate.
 *
 * @return string
 * 		The generated random string.
 */
function randomKey($length)
{
	$bytes = ceil($length / 1.33);
	$key = base64Encode(randomBytes($bytes, true));
	return substr($key, 0, $length);
}

/**
 * Encodes data in base64 using the alphabet ./0-9A-Za-z.
 *
 * @param string $str
 * 		The data to encode.
 *
 * @return string
 * 		The encoded data, as a string.
 */
function base64Encode($str)
{
	$from	= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	$to		= './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

	$str = substr(base64_encode($str), 0, -2);
	return strtr($str, $from, $to);
}

/**
 * Hashes the given password using PBKDF2.
 * Salt takes the form $F$<cost>$<blocks>$<salt> where the cost is a 2 digit
 * cost parameter, blocks is a 1 digit number defining how long the key should
 * be (block * 32) bytes, and the salt is a 22 digit salt using the alphabet
 * ./0-9A-Za-z.
 *
 * @param string $str
 * 		The password to hash.
 *
 * @param string $salt
 * 		A salt to base the hashing on.
 *
 * @return string
 * 		The hashed string, including the original salt.
 */
function pbkdf2($str, $salt)
{
	// Check if the given salt is valid or not
	if (!preg_match('%\$F\$(\d{2})\$(\d)\$([a-zA-Z0-9\./]{22})(.*)$%', $salt, $matches))
	{
		return null;
	}

	$workload = $matches[1];
	$key_blocks = $matches[2];
	$salt = $matches[3];

	unset($matches);

	$repetitions = pow(2, $workload + 3); // Increase the workload since PBKDF2 is faster than blowfish
	$output = '';

	for ($block = 0;$block < $key_blocks;$block++)
	{
		// Initial hash for this block
		$ib = $b = hash_hmac('sha256', $salt.pack('N', $block), $str, true);

		// Perform block iterations
		for ($i = 0;$i < $repetitions;$i++)
		{
			$ib ^= ($b = hash_hmac('sha256', $b, $str, true));
		}

		$output .= $ib;
	}

	// Return the salt + hash
	return '$F$'.str_pad($workload, 2, '0', STR_PAD_LEFT).'$'.$key_blocks.'$'.$salt.base64_encode($output);
}

/**
 * Hashes the given password, using blowfish when available, with
 * fallback to repeated hashing.
 *
 * @param string $str
 * 		The password to hash.
 *
 * @param int $workload
 * 		A cost parameter - the base 2 logarithm of the iteration count
 * 		for the underlying algorithm. Must be in the range 04-31.
 *
 * @return string
 * 		The hashed string, including the generated salt.
 */
function hash($str, $workload = 8)
{
	// Validate the workload is within sensible bounds
	if ($workload < 4)
	{
		$workload = 4;
	}

	if ($workload > 31)
	{
		$workload = 31;
	}

	// Generate a random salt and base64 encode it
	$salt = randomBytes(16, true);
	$salt = base64Encode($salt);

	// If we have blowfish, use it
	if (CRYPT_BLOWFISH === 1)
	{
		return crypt($str, '$2a$'.str_pad($workload, 2, '0', STR_PAD_LEFT).'$'.$salt);
	}

	// Fall back to PBKDF2
	return pbkdf2($str, '$F$'.str_pad($workload, 2, '0', STR_PAD_LEFT).'$1$'.$salt);
}

/**
 * Checks the given input against the stored hash.
 *
 * @param string $str
 * 		The user input to check.
 *
 * @param string $hash
 * 		The stored salt + hash.
 *
 * @return bool
 * 		TRUE if the given input matches the original
 * 		password, otherwise FALSE.
 */
function validate($str, $hash)
{
	// First try the fall back method, then crypt
	$answer = pbkdf2($str, $hash);
	if ($answer === null)
	{
		$answer = crypt($str, $hash);
	}

	return $answer === $hash;
}
