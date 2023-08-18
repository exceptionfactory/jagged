/*
 * Copyright 2023 Jagged Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.exceptionfactory.jagged.framework.crypto;

import com.exceptionfactory.jagged.FileKey;

import java.security.GeneralSecurityException;

/**
 * File Key Decryptor abstracts cipher operations for decrypting a File Key
 */
public interface FileKeyDecryptor {
    /**
     * Get File Key from Encrypted File Key
     *
     * @param encryptedFileKey Encrypted File Key
     * @param cipherKey Cipher Key for decrypting File Key
     * @return Decrypted File Key
     * @throws GeneralSecurityException Thrown on failure of decryption operations
     */
    FileKey getFileKey(EncryptedFileKey encryptedFileKey, CipherKey cipherKey) throws GeneralSecurityException;
}
