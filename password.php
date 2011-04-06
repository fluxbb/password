<?php

/**
* Copyright (C) 2011 FluxBB (http://fluxbb.org)
* License: LGPL - GNU Lesser General Public License (http://www.gnu.org/licenses/lgpl.html)
*/

class PasswordHash
{
	const HASH_ALGO = 'sha256';

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
	public static function random_bytes($length, $raw_output = false)
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
			$data .= pack('i', mt_rand());

		if (strlen($data) > $length)
			$data = substr($data, 0, $length);

		// If requested return the raw output
		if ($raw_output)
			return $data;

		// Otherwise return the data as a hex string
		return current(unpack('H*', $data));
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
	private static function base64_encode($str)
	{
		$from	= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
		$to		= './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

		$str = substr(base64_encode($str), 0, -2);
		return strtr($str, $from, $to);
	}

	/**
	 * Repeatedly hashes the given password according to the parameters
	 * in our custom salt. Salt takes the form $F$<cost>$<salt> where
	 * the cost is a 2 digit cost parameter, and the salt is a 22 digit
	 * salt using the alphabet ./0-9A-Za-z.
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
	private static function repeated_hash($str, $salt)
	{
		// Check if the given salt is valid or not
		if (!preg_match('%\$F\$(\d{2})\$([a-zA-Z0-9\./]{22})(.*)$%', $salt, $matches))
			return null;

		$workload = $matches[1] + 4; // Increase the workload since the custom hash is much faster than blowfish
		$salt = $matches[2];

		unset ($matches);

		// Hash the input depending on the workload
		$repetitions = pow(2, $workload);
		for ($i = 0;$i < $repetitions;$i++)
			$str = hash(self::HASH_ALGO, $salt.$str, true);

		// Return the salt + hash
		return '$F$'.str_pad($workload, 2, '0', STR_PAD_LEFT).'$'.$salt.self::base64_encode($str);
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
	public static function hash($str, $workload = 8)
	{
		// Validate the workload is within sensible bounds
		if ($workload < 4)
			$workload = 4;

		if ($workload > 31)
			$workload = 31;

		// Generate a random salt and base64 encode it
		$salt = self::random_bytes(16, true);
		$salt = self::base64_encode($salt);

		// If we have blowfish, use it
		if (CRYPT_BLOWFISH === 1)
			return crypt($str, '$2a$'.str_pad($workload, 2, '0', STR_PAD_LEFT).'$'.$salt);

		// Fallback to repeated hashing
		return self::repeated_hash($str, '$F$'.str_pad($workload, 2, '0', STR_PAD_LEFT).'$'.$salt);
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
	public static function validate($str, $hash)
	{
		// First try the fall back method, then crypt
		$answer = self::repeated_hash($str, $hash);
		if ($answer === null)
			$answer = crypt($str, $hash);

		return $answer === $hash;
	}
}
