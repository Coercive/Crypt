Coercive Security Crypt
=======================

Coercive Crypt is used to encrypt strings, texts, and then reopen them via a password.

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
