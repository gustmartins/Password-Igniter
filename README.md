# Password-Igniter
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?style=flat-square)]()

The perfect solution to storage and handle with passwords! The Password-Igniter Library is a simple bcrypt hashing library for CodeIgniter that can be used if your are going to storage user's password!
The Library is an adaption of PHPPass for use as a CodeIgniter library.

## Features

+ Generates _unique_ passwords
+ Makes your password storage more secure

## Requirements

- PHP version 5.6 or newer is recommended.
- CodeIgniter version 2.2.1+

## Instalation

To use the Password-Igniter Library you must copy the file `application/libraries/Password.php` to your own `application/libraries/` folder.

That's all! Have fun!

## Library Usage

> Below are some examples of what the Assets-Igniter does!

### Loading the Library

Your can load the Password-Igniter as you load any other library:

```php

$this->load->library('password');

```

### Hashing a password

Hashing passwords is easy! You'll pass the password string to the following function:

```php

$str = '1234'; // Please DO NOT use this as your password! Never!
$password = $this->password->hash($str);

```

**Important**: The function is supposed to return the encrypted password. But if you receive only the character `*` know that an error occurred.

### Checking a password

The next function will check the password by comparing the input password with the stored hash. So you are going to need both to check the password.
Since the function will return `true` or `false` depending on success, you can use an `if` clause as the following example:

```php

$str = '1234'; // Please DO NOT use this as your password! Never!

if ($this->password->check($str, $stored_hash))
{
	// Password matches stored hash
}
else
{
	// Password does not match stored hash
}

```

## Contributions

This package was created by [Gustavo Martins][GustMartins], but your help is welcome! Things you are welcome to do:

+ Report any bug you may encounter
+ Suggest a feature for the project

For more information about contributing to the project please, read the [Contributing Requirements][contrib].

## Change Log

Currently, the Password-Igniter Library is in the version **1.0.0**. See the full [Changelog][changelog] for more details.

[GustMartins]: https://github.com/GustMartins
[contrib]: https://github.com/GustMartins/Password-Igniter/blob/master/contributing.md
[changelog]: https://github.com/GustMartins/Password-Igniter/blob/master/changelog.md