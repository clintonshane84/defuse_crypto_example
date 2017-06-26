<?php
/**
 * Encryption library for crypting
 * and decrypting data
 * 
 * This library makes use of Defuse\php-encryption library:
 * https://github.com/defuse/php-encryption
 * 
 * This should be added to your composer.json file and installed
 * using composer install
 * 
 * Then using this library a Key must be generated using
 * Defuse\Crypto\Key::createNewRandomKey()
 * which returns an instance of Defuse\Crypto\Key which
 * then can be used to save a key to be used
 * $newKey = $result->saveToAsciiSafeString()
 * 
 * @package	CryptoLibrary
 * @author 	Clinton Wright
 * 
 * Example class that implements Defuse Crypto encryption library
 * Copyright (C) 2017 Clinton Wright
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
 
class CryptoLibrary
{

    private $skey = FALSE;
    public $errors = array();
    
    /**
     * Return all logged errors for this instance
     * 
     * @return array
     */
    public function getErrors()
    {
        return $this->errors;
    }
    
    /**
     * Encrypt a value
     * 
     * Returns the ciphertext for the encrypted value if successful else
     * boolean false if the function fails
     * 
     * @param $value string
     * @return mixed
     */
    public function safeEncrypt($value)
    {
        try {
            if (empty($value) == false && is_string($value)) {
                
                $ciphertext = \Defuse\Crypto\Crypto::Encrypt($value, $this->skey);
                
                return $ciphertext;
            } else {
                throw new \Exception('Failed to validate the required string value');
        }
        catch (\Defuse\Crypto\CryptoTestFailedException $e) {
            
            trigger_error('Cannot safely perform decryption with error: ' . $e->getMessage(), 'E_USER_WARNING');
        }
        catch (\Defuse\Crypto\CannotPerformOperationException $e) {
            
            trigger_error('Cannot safely perform decryption with error: ' . $e->getMessage(), 'E_USER_WARNING');
        }
        catch (\Exception $e) {
            
            trigger_error($e->getMessage(), 'E_USER_WARNING');
        }
        
        return false;
    }
    
    /**
     * Decrypt a ciphertext
     * 
     * Returns the decrypted value if successful else boolean false if
     * the function fails
     * 
     * @param $ciphertext string
     * @return mixed
     */
    public function safeDecrypt($ciphertext)
    {
        try {
            if (empty($ciphertext) == false && is_string($ciphertext)) {
                
                $decryptedtext = \Defuse\Crypto\Crypto::Decrypt($ciphertext, $this->skey);
                
                return $decryptedtext;
            } else {
                throw new \Exception('Failed to validate the ciphertext value');
            }
        }
        catch (\Defuse\Crypto\InvalidCiphertextException $e) {
            
            $this->errors[] = 'The ciphertext has been tampered with: ' . $e->getMessage();
        }
        catch (\Defuse\Crypto\CryptoTestFailedException $e) {
        
            $this->errors[] = 'Crypto test failed with error: ' . $e->getMessage();
        }
        catch (\Defuse\Crypto\CannotPerformOperationException $e) {
        
            $this->errors[] = 'Cannot safely perform decryption with error: ' . $e->getMessage();
        }
        catch (\Exception $e) {
            
            $this->errors[] = $e->getMessage();
        }
        
        return false;
    }
    
    /**
     * Set the hash key to use for encrypting and decrypting
     * Returns boolean true if key is successfully set
     * 
     * @param $key string
     * @return boolean
     */
    public function setKey($key)
    {
        try {
            
            if (empty($key) == false && is_string($key)) {
                
                try {
                    
                    $result = \Defuse\Crypto\Key::loadFromAsciiSafeString($key);
                } catch (\Exception $e) {
                    
                    throw new \Exception("No key setup for system");
                }

                if ($result && is_object($result)) {
                    
                    if ($result instanceof \Defuse\Crypto\Key) {
                        
                        $this->skey = $result;
                        return true;
                    }
                }
            } else {
                throw new \Exception('Could not validate the key argument');
            }
        }
        catch (\Defuse\Crypto\CryptoTestFailedException $e) {
            
            $this->errors[] = $e->getMessage();
        }
        catch (\Defuse\Crypto\CannotPerformOperationException $e) {
            
            $this->errors[] = 'Cannot safely perform decryption with error: ' . $e->getMessage();
        }
        catch (\Exception $e) {
            
            $this->errors[] = $e->getMessage();
        }
        
        return false;
    }
}
