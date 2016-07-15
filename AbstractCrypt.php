<?php
namespace Coercive\Security\Crypt;

use Exception;

/**
 * AbstractCrypt
 * PHP Version 	5
 *
 * @version		1
 * @package 	Coercive\Security\Crypt
 * @link		@link https://github.com/Coercive/Crypt
 *
 * ORIGINAL AUTHOR :
 * @author      Taylor Hornby - Defuse
 * @link        https://github.com/defuse
 * @copyright   (c) 2014-2015, Taylor Hornby - All rights reserved.
 *
 * MODIFIED BY :
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2016 - 2017 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class AbstractCrypt {

    const KEY_FUNCTION = 'sha512';
    const KEY_BYTE_SIZE = 128;
    const CIPHER_METHOD = 'aes-256-cbc';
    const HASH_FUNCTION = 'sha256';
    const MAC_BYTE_SIZE = 32;
    const ENCRYPTION_INFO = 'Security|KeyForEncryption';
    const AUTHENTICATION_INFO = 'Security|KeyForAuthentication';

    /**
     * EXCEPTION
     *
     * @param string $sMessage
     * @param int $sLine
     * @param string $sMethod
     * @throws Exception
     */
    static protected function _exception($sMessage, $sLine = __LINE__, $sMethod = __METHOD__) {
        throw new Exception("$sMessage \nMethod :  $sMethod \nLine : $sLine");
    }

    /**
     * Returns a random binary string of length $octets bytes.
     *
     * @param int $iOctets
     * @return string (raw binary)
     * @throws Exception
     */
    static protected function _secureRandom($iOctets) {
        self::_isFunctionExists('openssl_random_pseudo_bytes');
        $bSecure = false;
        $sRandom = openssl_random_pseudo_bytes($iOctets, $bSecure);
        if ($sRandom === false || $bSecure === false) { self::_exception ('openssl_random_pseudo_bytes() failed.', __LINE__, __METHOD__); }
        return $sRandom;
    }

    /**
     * Use HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     *
     * @param string $sHash Hash Function
     * @param string $sIKM Initial Keying Material
     * @param int $iLength How many bytes?
     * @param string $sInfo What sort of key are we deriving? [optional]
     * @param string $sSalt [optional]
     * @return string
     * @throws Exception
     */
    static protected function _HKDF($sHash, $sIKM, $iLength, $sInfo = '', $sSalt = null) {

        // Find the correct digest length as quickly as we can.
        $iDigestLength = self::MAC_BYTE_SIZE;
        if ($sHash != self::HASH_FUNCTION) {
            $iDigestLength = self::_strlen(hash_hmac($sHash, '', '', true));
        }

        // Sanity-check the desired output length.
        if (empty($iLength) || !is_int($iLength) || $iLength < 0 || $iLength > 255 * $iDigestLength) {
            self::_exception('Bad output length requested of HKDF.', __LINE__, __METHOD__);
        }

        // if [salt] not provided, is set to a string of HashLen zeroes.
        if (is_null($sSalt)) { $sSalt = str_repeat("\x00", $iDigestLength); }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $sPRK = hash_hmac($sHash, $sIKM, $sSalt, true);

        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        if (self::_strlen($sPRK) < $iDigestLength) {
            self::_exception('Length of PRK < '.$iDigestLength, __LINE__, __METHOD__);
        }

        /** @var string T(0) = '' */
        $sT = '';

        /** @var string $sLastBlock */
        $sLastBlock = '';

        # Process
        for ($i = 1; self::_strlen($sT) < $iLength; ++$i) {

            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $sLastBlock = hash_hmac($sHash, $sLastBlock . $sInfo . chr($i), $sPRK, true );

            // T = T(1) | T(2) | T(3) | ... | T(N)
            $sT .= $sLastBlock;
        }

        // ORM = first L octets of T
        $sORM = self::_substr($sT, 0, $iLength);
        if ($sORM === false) { self::_exception('Bad ORM', __LINE__, __METHOD__); }
        return $sORM;
    }

    /**
     * Unauthenticated message encryption.
     *
     * @param string $sPlainText
     * @param string $sKey
     * @param string $sIv
     * @return string
     * @throws Exception
     */
    static protected function _plainEncrypt($sPlainText, $sKey, $sIv) {
        # Verify
        self::_isConstantExists('OPENSSL_RAW_DATA');
        self::_isFunctionExists('openssl_encrypt');

        /** @var string $sCipherText */
        $sCipherText = openssl_encrypt($sPlainText, self::CIPHER_METHOD, $sKey, OPENSSL_RAW_DATA, $sIv);
        if ($sCipherText === false) { self::_exception('openssl_encrypt() failed.', __LINE__, __METHOD__); }
        return $sCipherText;
    }

    /**
     * Unauthenticated message deryption.
     *
     * @param string $sCipherText
     * @param string $sKey
     * @param string $sIv
     * @return string
     * @throws Exception
     */
    static protected function _plainDecrypt($sCipherText, $sKey, $sIv) {
        # Verify
        self::_isConstantExists('OPENSSL_RAW_DATA');
        self::_isFunctionExists('openssl_decrypt');

        /** @var string $sPlainText */
        $sPlainText = openssl_decrypt($sCipherText, self::CIPHER_METHOD, $sKey, OPENSSL_RAW_DATA, $sIv);
        if ($sPlainText === false) { self::_exception('openssl_decrypt() failed.', __LINE__, __METHOD__); }
        return $sPlainText;
    }

    /**
     * Verify a HMAC without crypto side-channels
     *
     * @staticvar boolean $bNative Use native hash_equals()?
     * @param string $sCorrectHMAC HMAC string (raw binary)
     * @param string $sMessage Ciphertext (raw binary)
     * @param string $sKey Authentication key (raw binary)
     * @return bool
     * @throws Exception
     */
    static protected function _verifyHMAC($sCorrectHMAC, $sMessage, $sKey) {

        # SINGLETON Detect
        static $bNative = null;
        if ($bNative === null) { $bNative = function_exists('hash_equals'); }

        /** @var string $sMessageHMAC */
        $sMessageHMAC = hash_hmac(self::HASH_FUNCTION, $sMessage, $sKey, true);

        # Classic hash_equals
        if ($bNative) { return hash_equals($sCorrectHMAC, $sMessageHMAC); }

        // We can't just compare the strings with '==', since it would make
        // timing attacks possible. We could use the XOR-OR constant-time
        // comparison algorithm, but I'm not sure if that's good enough way up
        // here in an interpreted language. So we use the method of HMACing the
        // strings we want to compare with a random key, then comparing those.
        // NOTE: This leaks information when the strings are not the same
        // length, but they should always be the same length here. Enforce it:
        if (self::_strlen($sCorrectHMAC) !== self::_strlen($sMessageHMAC)) {
            self::_exception('Computed and included HMACs are not the same length.', __LINE__, __METHOD__);
        }

        /** @var string $sBlind */
        $sBlind = self::_secureRandom(self::KEY_BYTE_SIZE);
        $sMessageCompare = hash_hmac(self::HASH_FUNCTION, $sMessageHMAC, $sBlind);
        $sCorrectCompare = hash_hmac(self::HASH_FUNCTION, $sCorrectHMAC, $sBlind);
        return $sCorrectCompare === $sMessageCompare;
    }


    /**
     * If the constant doesn't exist, throw an exception
     *
     * @param string $sName ; Constant Name
     * @throws Exception
     */
    static protected function _isConstantExists($sName) {
        if (!defined($sName)) {
            self::_exception('Constant '. htmlspecialchars($sName) .' does not exist.', __LINE__, __METHOD__);
        }
    }

    /**
     * If the function doesn't exist, throw an exception
     *
     * @param string $sName : Function name
     * @throws Exception
     */
    static protected function _isFunctionExists($sName) {
        if (!function_exists($sName)) {
            self::_exception('Function '. htmlspecialchars($sName) .' does not exist.', __LINE__, __METHOD__);
        }
    }

    /**
     * Safe string length
     *
     * @staticvar boolean $exists
     * @param string $sString
     * @return int
     * @throws Exception
     */
    static protected function _strlen($sString) {

        # SINGLETON DETECT
        static $bExists = null;
        if ($bExists === null) { $bExists = function_exists('mb_strlen'); }

        # Classic STRLEN
        if (!$bExists) { return strlen($sString); }

        # Calcul 8 Bits
        $iLength = mb_strlen($sString, '8bit');
        if ($iLength === false) { self::_exception('mb_strlen() failed.', __LINE__, __METHOD__); }
        return $iLength;

    }

    /**
     * Safe substring
     *
     * @staticvar boolean $exists
     * @param string $sString
     * @param int $iStart [optional]
     * @param int $iLength [optional]
     * @return string
     */
    static protected function _substr($sString, $iStart = 0, $iLength = null) {

        # SINGLETON DETECT
        static $bExists = null;
        if ($bExists === null) { $bExists = function_exists('mb_substr'); }

        # Define Length
        if (!$iLength) { $iLength = $iStart >= 0 ? self::_strlen($sString) - $iStart : $iLength = -$iStart; }

        # Classic SUBSTR
        if (!$bExists) { return substr($sString, $iStart, $iLength); }

        # Calcul 8 Bits
        return mb_substr($sString, $iStart, $iLength, '8bit');

    }

}