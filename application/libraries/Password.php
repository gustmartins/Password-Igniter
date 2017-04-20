<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Password Class for Codeigniter
 *
 * This class helps to cript users password using bcrypt
 *
 * @package		Password
 * @subpackage	Library
 * @category	Library
 * @author		Gustavo Martins <gustavo_martins92@hotmail.com>
 * @link		https://github.com/GustMartins/Password-Igniter
 * @version 	1.0.0
 */
class Password {

	/**
	 *	How many iterations of hashing should occur
	 * 
	 *	@var integer
	 */
	public $iteration_count		= 8;

	/**
	 *	True if the hash should be portable
	 * 
	 *	@var	boolean
	 */
	public $portable_hashes		= FALSE;
	
	// --------------------------------------------------------------------
	
	/**
	 *	@var	string
	 */
	protected $_characters64	= './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

	/**
	 *	@var string
	 */
	protected $_blowfish64		= './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

	/**
	 *	@var	string
	 */
	protected $_random_state	= '';
	
	// --------------------------------------------------------------------
	
	/**
	 *	Constructor - Sets Hash Preferences
	 *
	 *	The constructor can be passed an array of config values
	 *
	 *	@param	array	$config = array()
	 *	@return	void
	 */
	function __construct(array $config = array())
	{
		$this->initialize($config);

		if ($this->iteration_count < 4 || $this->iteration_count > 31)
		{
			$this->set_iteration_count();
		}

		log_message('info', 'Password Class Initialized');
	}
	
	// --------------------------------------------------------------------
	
	/**
	 *	Initialize preferences
	 *
	 *	@param	array		$config
	 *	@return	Password
	 */
	public function initialize(array $config = array())
	{
		$this->clear();

		foreach ($config as $key => $val)
		{
			if (isset($this->$key))
			{
				$method = 'set_'.$key;

				if (method_exists($this, $method))
				{
					$this->$method($val);
				}
			}
		}

		if ( ! function_exists('getmypid'))
		{
			$this->_set_random_state(microtime());
		}
		else
		{
			$this->_set_random_state(microtime().getmypid());
		}

		return $this;
	}
	
	// --------------------------------------------------------------------
	
	/**
	 *	Initialize the Password Data
	 *
	 *	@param	bool
	 *	@return	Password
	 */
	public function clear()
	{
		$this->iteration_count	= 8;
		$this->portable_hashes	= FALSE;
		$this->_characters64	= './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
		$this->_blowfish64		= './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		$this->_random_state	= '';

		return $this;
	}
	
	// --------------------------------------------------------------------
	
	/**
	 *	Set Iteration count
	 *
	 *	@param	integer
	 *	@return	Password
	 */
	public function set_iteration_count($count = 8)
	{
		$this->iteration_count = (integer) $count;
		return $this;
	}
	
	// --------------------------------------------------------------------
	
	/**
	 *	Set portable hash boolean
	 *	
	 *	@param	boolean
	 *	@return	Password
	 */
	public function set_portable_hashes($portable = FALSE)
	{
		$this->portable_hashes = (boolean) $portable;
		return $this;
	}
	
	// --------------------------------------------------------------------
	
	/**
	 *	Set random state
	 *	
	 *	@param	boolean
	 *	@return	Password
	 */
	protected function _set_random_state($state)
	{
		$this->_random_state = $state;
		return $this;
	}
	
	// --------------------------------------------------------------------
	
	/**
	 *	Hash a password
	 * 
	 *	@param	string	$password	The password to be hashed
	 *	@return	string				Hashed password
	 */
	public function hash($password)
	{
		$random_chars = '';

		if ( ! $this->portable_hashes && CRYPT_BLOWFISH == 1)
		{
			$random_chars = $this->_get_random_bytes();

			$hashed_pass = crypt($password, $this->_get_salt_blowfish($random_chars));

			if (strlen($hashed_pass) == 60)
			{
				return $hashed_pass;
			}
		}

		if ( ! $this->portable_hashes && CRYPT_EXT_DES == 1)
		{
			if (strlen($random_chars) < 3)
			{
				$random_chars = $this->_get_random_bytes(3);
			}

			$hashed_pass = crypt($password, $this->_get_salt_extended($random_chars));

			if (strlen($hashed_pass) == 20)
			{
				return $hashed_pass;
			}
		}

		if (strlen($random_chars) < 6)
		{
			$random_chars = $this->_get_random_bytes(6);
		}

		$hashed_pass = $this->_private_crypt($password, $this->_get_salt_private($random_chars));

		if (strlen($hashed_pass) == 34)
		{
			return $hashed_pass;
		}

		return '*';
	}

	// --------------------------------------------------------------------
	
	/**
	 *	Check a password
	 * 
	 *	@param	string
	 *	@param	string	$stored_hash	The password to compare with
	 *	@return	boolean
	 */
	public function check($password, $stored_hash)
	{
		$hash = $this->_private_crypt($password, $stored_hash);

		if ($hash[0] == '*')
		{
			$hash = crypt($password, $stored_hash);
		}

		return $hash == $stored_hash;
	}
	
	// --------------------------------------------------------------------
	
	/**
	 *  Generates $n random bytes
	 *
	 *  @param    integer   $n
	 *  @return   string
	 */
	protected function _get_random_bytes($n = 16)
	{
		$output = '';

		if (is_readable('/dev/urandom') && ($fh = @fopen('/dev/urandom', 'rb')))
		{
			$output = fread($fh, $n);
			fclose($fh);
		}

		if (strlen($output) < $n)
		{
			$output = '';

			for ($i = 0; $i < $n; $i += 16)
			{
				$this->_set_random_state(md5(microtime().$this->_random_state));
				$output .= pack('H*', md5($this->_random_state));
			}

			$output = substr($output, 0, $n);
		}

		return $output;
	}
	
	// --------------------------------------------------------------------

	/**
	 *  Generates the salt blowfish
	 *
	 *  @param    string   $str
	 *  @return   string
	 */
	protected function _get_salt_blowfish($str)
	{
		$output  = '$2a$';
		$output .= chr(ord('0') + $this->iteration_count / 10);
		$output .= chr(ord('0') + $this->iteration_count % 10);
		$output .= '$';

		$i = 0;
		do
		{
			$ctext = ord($str[$i++]);
			$output .= $this->_blowfish64[$ctext >> 2];
			$ctext = ($ctext & 0x03) << 4;

			if ($i >= 16)
			{
				$output .= $this->_blowfish64[$ctext];
				break;
			}

			$ctext2 = ord($str[$i++]);
			$ctext |= $ctext2 >> 4;
			$output .= $this->_blowfish64[$ctext];
			$ctext = ($ctext2 & 0x0f) << 2;
			$ctext2 = ord($str[$i++]);
			$ctext |= $ctext2 >> 6;
			$output .= $this->_blowfish64[$ctext];
			$output .= $this->_blowfish64[$ctext2 & 0x3f];
		}
		while (1);

		return $output;
	}
	
	// --------------------------------------------------------------------

	/**
	 *  Generates extended salt
	 *
	 *  @param    string   $str
	 *  @return   string
	 */
	protected function _get_salt_extended($str)
	{
		$count_log = min($this->iteration_count + 8, 24);
		$count = (1 << $count_log) - 1;

		$output  = '_';
		$output .= $this->_characters64[$count & 0x3f];
		$output .= $this->_characters64[($count >> 6) & 0x3f];
		$output .= $this->_characters64[($count >> 12) & 0x3f];
		$output .= $this->_characters64[($count >> 18) & 0x3f];
		$output .= $this->_encode64($str, 3);

		return $output;
	}
	
	// --------------------------------------------------------------------

	/**
	 *  Generates a private crypt
	 *
	 *  @param    string   $password
	 *  @param    string   $setting
	 *  @return   string
	 */
	protected function _private_crypt($password, $setting)
	{
		$output = '*0';
		if (substr($setting, 0, 2) == $output)
		{
			$output = '*1';
		}

		$id = substr($setting, 0, 3);
		if ($id !== '$P$' && $id !== '$H$')
		{
			return $output;
		}

		$count_log = strpos($this->_characters64, $setting[3]);
		if ($count_log < 7 || $count_log > 30)
		{
			return $output;
		}

		$count = 1 << $count_log;

		$salt = substr($setting, 4, 8);
		if (strlen($salt) != 8)
		{
			return $output;
		}

		if (PHP_VERSION >= '5')
		{
			$hash = md5($salt.$password, TRUE);
			do
			{
				$hash = md5($hash.$password, TRUE);
			}
			while (--$count);
		}
		else
		{
			$hash = pack('H*', md5($salt.$password));
			do
			{
				$hash = pack('H*', md5($hash.$password));
			}
			while (--$count);
		}

		$output  = substr($setting, 0, 12);
		$output .= $this->_encode64($hash, 16);

		return $output;
	}

	// --------------------------------------------------------------------

	/**
	 *  Generates salt to use with private crypt
	 *
	 *  @param    string   $str
	 *  @return   string
	 */
	protected function _get_salt_private($str)
	{
		$output  = '$P$';
		$output .= $this->_characters64[min($this->iteration_count + ((PHP_VERSION >= '5') ? 5 : 3), 30)];
		$output .= $this->_encode64($str, 6);

		return $output;
	}
	
	// --------------------------------------------------------------------

	/**
	 *  Encodes a string
	 *
	 *  @param    string    $str
	 *  @param    integer   $count
	 *  @return   string
	 */
	protected function _encode64($str, $count)
	{
		$output = '';

		$i = 0;
		do
		{
			$value = ord($str[$i++]);
			$output .= $this->_characters64[$value & 0x3f];
			
			if ($i < $count)
			{
				$value |= ord($str[$i]) << 8;
			}
			$output .= $this->_characters64[($value >> 6) & 0x3f];

			if ($i++ >= $count)
			{
				break;
			}

			if ($i < $count)
			{
				$value |= ord($str[$i]) << 16;
			}
			$output .= $this->_characters64[($value >> 12) & 0x3f];

			if ($i++ >= $count)
			{
				break;
			}
			$output .= $this->_characters64[($value >> 18) & 0x3f];
		}
		while ($i < $count);

		return $output;
	}
}
