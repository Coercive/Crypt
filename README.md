Coercive Security Crypt
=======================

Coercive Crypt is used to encrypt strings, texts, and then reopen them via a password.
This is a remake of an already existing library.
Please see copyright bellow.


**ORIGINAL AUTHOR**
- @author      Taylor Hornby - Defuse
- @link        https://github.com/defuse
- @copyright   (c) 2014-2015, Taylor Hornby - All rights reserved.
- @website     Enterprises <https://paragonie.com>.


Get
---
```
composer require coercive/crypt
```

Usage
-----
```php
use Coercive\Security\Crypt

# PLAIN TEXT
$TEXT = 'Text for example';

# CREATE A KEY
$KEY = Crypt::createNewKey('My password for the test');

# OR CREATE A RANDOM
$KEY = Crypt::createNewRandomKey();

# ENCRYPT A TEXT
$CIPHERTEXT = Crypt::encrypt($TEXT, $KEY);

# GET PLAIN TEXT
$PlainText = Crypt::decrypt($CIPHERTEXT, $KEY);

```
