<?php

  /**
   * This class offers a wrapper to the php5-mcrypt module for encrypting and
   * decrypting data. The encrypted data can be returned and expected in binary
   * or hexadecimal form.
   * 
   * <code>
   * $encryption = new expalasEncryption();
   * 
   * // Encrypt text
   * $encrypted_text = $encryption->encrypt('this text is unencrypted');
   * // Decrypt text
   * $decrypted_text = $encryption->decrypt($encrypted_text); 
   * </code>           
   *    
   * @copyright  Copyright (c) 2013, Björn Ebbrecht
   * @author Björn Ebbrecht <ebbrecht@expalas.de>
   * @package expalasEncryption
   * @version 1.0 
   */                 
  class expalasEncryption {
  
    /**
     * The encryption/decryption algorithm.
     * @var string
     */                   
    private $cypher = MCRYPT_BLOWFISH;
    
    /**
     * The encryption/decryption mode.
     * @var string
     */   
    private $mode = MCRYPT_MODE_CBC;
    
    /**
     * The very secret key for encrypting.
     * @var string
     */   
    private $key = 'e2bf5a831914c';
    
    /**
     * This method encrypts a given string and returns the encrypted data in
     * binary or hexadecimal form.
     * 
     * @param string $string the string to be encrypt
     * @param bool $hex optional returns the encrypted data in hexadecimal form
     * @return string the encrypted data
     */                                  
    public function encrypt($string, $hex = true) {
    
      /**
       * Initializing the mcrypt module.
       */             
      $td = mcrypt_module_open($this->cypher, '', $this->mode, '');
      
      /**
       * Create initialization vector. Constant MCRYPT_RAND is also supported on
       * windows, so we can offer cross-platform running.
       */                    
      $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
      
      /**
       * Initializing all buffers needed for encryption
       */             
      mcrypt_generic_init($td, $this->key, $iv);
      
      /**
       * encrypt the given string
       */             
      $crypttext = mcrypt_generic($td, $string);
      
      /**
       * Deinitializes the mcrypt-module, deleting from ram.
       */             
      mcrypt_generic_deinit($td);
      
      /**
       * Returning the encrypted data either in a binary or hexadecimal way
       */             
      if ($hex === true) {
        $return = bin2hex($iv.$crypttext);
      } else {
        $return = $iv.$crypttext;
      }
      
      return $return;
        
    }
    
    /**
     * This method decrypts a given string and returns the decrypted data as a
     * string. 
     * 
     * @param string $string the encrypted data (binary or hexadecimal)
     * @param bool $hex optional expects binary data, if true hexadecimal
     * @return (string|bool) decrypted version of the encrypted string or false
     */                                 
    public function decrypt($string, $hex = true) {
    
      /**
       * Converting the given string from hex to bin if needed.
       */             
      if ($hex === true) {
        $string = pack("H*" , $string);
      }
      
      /**
       * Initializing the mcrypt module.
       */   
      $td = mcrypt_module_open($this->cypher, '', $this->mode, '');
      
      /**
       * Getting the initialization vector for decrypting via substring.
       */             
      $ivsize = mcrypt_enc_get_iv_size($td);
      $iv = substr($string, 0, $ivsize);
      
      /**
       * Getting the encrypted text via substring
       */             
      $crypttext = substr($string, $ivsize);
      
      if ($iv) {
      
        /**
         * Decrypt data and return.
         */                 
        mcrypt_generic_init($td, $this->key, $iv);
        return mdecrypt_generic($td, $crypttext);
      
      } else {
      
        return false;
      
      }
    }
  }

?>
