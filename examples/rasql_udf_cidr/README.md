MySQL already supports a [number of string functions natively](http://dev.mysql.com/doc/refman/5.6/en/string-functions.html). However, these string functions are not exhaustive and other string functions can ease the development of MySQL-based applications. Users coming from a PHP or Perl background, for instance, may expect to find their entire set of string functions in MySQL. `lib_mysqludf_str` aims to offer a library of string functions which complement the native ones.

The following functions are currently supported in the `lib_mysqludf_str` library:

 - [`str_numtowords`](#str_numtowords) – converts a number to a string.
 - [`str_rot13`](#str_rot13) – performs the ROT13 transform on a string.
 - [`str_shuffle`](#str_shuffle) – randomly shuffles the characters of a string.
 - [`str_translate`](#str_translate) – replaces characters contained in srcchar with the corresponding ones in dstchar.
 - [`str_ucfirst`](#str_ucfirst) – uppercases the first character of a string.
 - [`str_ucwords`](#str_ucwords) – transforms to uppercase the first character of each word in a string.
 - [`str_xor`](#str_xor) – performs a byte-wise exclusive OR (XOR) of two strings.
 - [`str_srand`](#str_srand) – generates a string of cryptographically secure pseudo-random bytes.

Use [`lib_mysqludf_str_info()`](#lib_mysqludf_str_info) to obtain information about the currently-installed version of `lib_mysqludf_str`.

## Installation

### Windows

Binaries are provided for 32-bit and 64-bit MySQL, Intel/x86 architecture:

* [32-bit `lib_mysqludf_str` 0.5](https://github.com/mysqludf/lib_mysqludf_str/blob/downloads/Downloads/lib_mysqludf_str-0.5-x86.zip?raw=true) ([sig](https://raw.github.com/mysqludf/lib_mysqludf_str/downloads/Downloads/lib_mysqludf_str-0.5-x86.zip.asc))
* [64-bit `lib_mysqludf_str` 0.5](https://github.com/mysqludf/lib_mysqludf_str/blob/downloads/Downloads/lib_mysqludf_str-0.5-x64.zip?raw=true) ([sig](https://raw.github.com/mysqludf/lib_mysqludf_str/downloads/Downloads/lib_mysqludf_str-0.5-x64.zip.asc))

Please verify the GPG signature. If you are not used to the command-line interface of `gpg`, an excellent GPG GUI for Windows is [GnuPT](http://www.gnupt.de/site/index.php?option=com_content&view=article&id=73&Itemid=529).

Alternatively, `lib_mysqludf_str` may be built from source using the provided Visual Studio solution. Install an edition of Visual Studio 2012 for Windows Desktop ([Visual Studio Express 2012 for Windows Desktop](http://www.microsoft.com/visualstudio/eng/products/visual-studio-express-for-windows-desktop) is fine) and then double-click on `lib_mysqludf_str.sln`.

To complete the installation, refer to [`README.win_x86.txt`](https://github.com/mysqludf/lib_mysqludf_str/blob/master/README.win_x86.txt), or [`README.win_x64.txt`](https://github.com/mysqludf/lib_mysqludf_str/blob/master/README.win_x64.txt) for 64-bit `lib_mysqludf_str`.

### UNIX/Linux

`lib_mysqludf_str` uses an Autoconf build system, so the standard `./configure` and `make` procedure applies:

<pre>
./configure --prefix=/usr/local/lib_mysqludf_str-0.5
make && make install
</pre>

The listed prefix is just a suggestion; it can, of course, be changed to some other installation location.

Custom configure options supported by the project include:

<pre>
  --with-max-random-bytes=INT
                          Set the maximum number of bytes that can be
                          generated with a single call to str_srand [4096]
  --with-mysql=[ARG]      use MySQL client library [default=yes], optionally
                          specify path to mysql_config
</pre>

The shared object (SO file) must be copied to MySQL's plugin directory, which can be determined by executing the following SQL:

    SHOW VARIABLES LIKE 'plugin_dir';

To then load the functions:

<pre>
mysql -u root -p &lt; installdb.sql
</pre>

## Uninstallation

  * In MySQL, source `uninstalldb.sql` as root.
  * Delete the plugin from MySQL's plugin folder.

## Documentation

### str_numtowords

`str_numtowords` converts numbers to English word(s). All integers in the range [-2<sup>63</sup>, 2<sup>63</sup> - 1] are supported.

##### Syntax

    str_numtowords(num)

##### Parameter and Return Value

`num`
:   The integer number to be converted to a string. If `num` is not an integer type or it is NULL, an error will be returned.

returns
:   The string spelling the given number in English.

##### Example

Converting 123456 to a string:

    SELECT str_numtowords(123456) AS price;

yields this result:

<pre>
+----------------------------------------------------------+
| price                                                    |
+----------------------------------------------------------+
| one hundred twenty-three thousand four hundred fifty-six |
+----------------------------------------------------------+
</pre>

### str_rot13

`str_rot13` performs the [ROT13 transform](http://en.wikipedia.org/wiki/ROT13) on a string, shifting each character by 13 places in the alphabet, and wrapping back to the beginning if necessary. Non-alphabetic characters are not modified.

##### Syntax

    str_rot13(subject)

##### Parameter and Return Value

`subject`
:   The string to be transformed. If `subject` is not a string type or it is NULL, an error will be returned.

returns
:   The original string with each letter shifted by 13 places in the alphabet.

##### Examples

Applying the ROT13 transform:

    SELECT str_rot13('secret message') AS crypted;

yields this result:

<pre>
+----------------+
| crypted        |
+----------------+
| frperg zrffntr |
+----------------+
</pre>

Reversing the ROT13 transform (applying ROT13 again, as the transform is its own inverse):

    SELECT str_rot13('frperg zrffntr') AS decrypted;

yields this result:

<pre>
+----------------+
| decrypted      |
+----------------+
| secret message |
+----------------+
</pre>

### str_shuffle

The `str_shuffle` function takes a string and randomly shuffles its characters, returning one of the possible permutations.

##### Syntax

    str_shuffle(subject)

##### Parameter and Return Value

`subject`
:   A string value to be shuffled. If `subject` is not a string type or it is NULL, an error will be returned.

returns
:   A string value representing one of the possible permutations of the characters of `subject`.

##### Example

Shuffling a string:

    SELECT str_shuffle('shake me!') AS nonsense;

yields a result like this:

<pre>
+-----------+
| nonsense  |
+-----------+
| esm a!khe |
+-----------+
</pre>

### str_translate

The `str_translate` function scans each character in the subject string and replaces every occurrence of a character that is contained in `srcchar` with the corresponding char in `dstchar`.

##### Syntax

    str_translate(subject, srcchar, dstchar)

##### Parameters and Return Value

`subject`
:   A string value whose characters have to be transformed. If `subject` is not a string type or it is NULL, an error will be returned.

`srcchar`
:   A string value containing the characters to be searched and replaced. If `srcchar` is not a string type or it is NULL, an error will be returned. `srcchar` must contain the same number of characters as `dstchar`.

`dstchar`
:   A string value containing the characters which will replace the corresponding ones in `srcchar`. If `dstchar` is not a string type or it is NULL, an error will be returned. `dstchar` must contain the same number of characters as `srcchar`.

returns
:   A string value that is a copy of `subject` but in which each character present in `srcchar` replaced with the corresponding character in `dstchar`.

##### Example

Replacing 'a' with 'x' and 'b' with 'y':

    SELECT str_translate('a big string', 'ab', 'xy') AS translated;

yields this result:

<pre>
+--------------+
| translated   |
+--------------+
| x yig string |
+--------------+
</pre>

### str_ucfirst

The `str_ucfirst` function is the MySQL equivalent of PHP's [`ucfirst()`](http://www.php.net/manual/en/function.ucfirst.php). It takes a string and uppercases the first character.

##### Syntax

    str_ucfirst(subject)

##### Parameter and Return Value

`subject`
:   A string value whose first character will be transformed into uppercase. If `subject` is not a string type or it is NULL, an error will be returned.

returns
:   A string value with the first character of `subject` capitalized, if that character is alphabetic.

##### Example

    SELECT str_ucfirst('sample string') AS capitalized;
	
yields this result:

<pre>
+---------------+
| capitalized   |
+---------------+
| Sample string |
+---------------+
</pre>

##### See Also

  * `str_ucwords`

### str_ucwords

The `str_ucwords` function is the MySQL equivalent of PHP's [`ucwords()`](http://www.php.net/manual/en/function.ucwords.php). It takes a string and transforms the first character of each of word into uppercase.

##### Syntax

    str_ucwords(subject)

##### Parameter and Return Value

`subject`
:   A string value where the	first character of each string will be transformed into uppercase. If `subject` is not a string type or it is NULL, an error will be returned.

returns
:   A string value with the first character of each word in `subject` capitalized, if such characters are alphabetic.

##### Example

    SELECT str_ucwords('a string composed of many words') AS capitalized;
	
yields this result:

<pre>
+---------------------------------+
| capitalized                     |
+---------------------------------+
| A String Composed Of Many Words |
+---------------------------------+
</pre>

##### See Also

  * `str_ucfirst`

### str_xor

The `str_xor` function performs a byte-wise exclusive OR (XOR) of two strings.

##### Syntax

    str_xor(string1, string2)

##### Parameters and Return Value

`string1`
:   The first string. If `string1` is not a string or is NULL, then an error is returned.

`string2`
:   The second string. If `string2` is not a string or is NULL, then an error is returned.

returns
:   The string value that is obtained by XORing each byte of `string1` with the corresponding byte of `string2`.

Note that if `string1` or `string2` is longer than the other, then the shorter string is considered to be padded with enough trailing NUL bytes (0x00) for the two strings to have the same length.

##### Examples

    SELECT HEX(str_xor(UNHEX('0E33'), UNHEX('E0'))) AS result;
	
yields this result:

<pre>
+--------+
| result |
+--------+
| EE33   |
+--------+
</pre>
	
    SELECT HEX(str_xor('Wiki', UNHEX('F3F3F3F3'))) AS result;
	
yields this result:

<pre>
+----------+
| result   |
+----------+
| A49A989A |
+----------+
</pre>

##### Since

Version 0.2

##### See Also

  * "[XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher)". Wikipedia.

### str_srand

The `str_srand` function generates a string of random bytes from a cryptographically secure pseudo random number generator (CSPRNG).

##### Syntax

    str_srand(length)

##### Parameter and Return Value

`length`
:   The number of pseudo-random bytes to generate, and the length of the string. If `length` is not a non-negative integer or is NULL, then an error is returned. **Note:** To prevent denial of service, `length` is limited to the compile-time constant `MAX_RANDOM_BYTES`. By default, `MAX_RANDOM_BYTES` is 4096 (4 KiB).

returns
:   A string value comprised of `length` cryptographically secure pseudo-random bytes.

##### Example

    SELECT str_srand(5) AS result;
	
yields a random string containing 5 bytes.

<pre>
mysql&gt; SELECT LENGTH(str_srand(5)) as len;
+-----+
| len |
+-----+
|   5 |
+-----+
</pre>

##### Since

Version 0.3

##### See Also

  * "[CSPRNG](https://en.wikipedia.org/wiki/CSPRNG)". Wikipedia.

### lib_mysqludf_str_info

The `lib_mysqludf_str_info` function returns information about the currently-installed version of `lib_mysqludf_str`.

##### Syntax

    lib_mysqludf_str_info()

##### Return Value

returns
:   A string value containing the version of `lib_mysqludf_str` that is installed.

##### Example

    SELECT lib_mysqludf_str_info() AS info;
	
yields this result:

<pre>
+------------------------------+
| info                         |
+------------------------------+
| lib_mysqludf_str version 0.5 |
+------------------------------+
</pre>
