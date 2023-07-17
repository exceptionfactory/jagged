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
package com.exceptionfactory.jagged.scrypt;

import com.exceptionfactory.jagged.framework.crypto.CipherKey;

import java.security.GeneralSecurityException;

/**
 * Abstraction for producing Wrap Key derived from scrypt parameters
 */
interface DerivedWrapKeyProducer {
    /**
     * Get Wrap Key
     *
     * @param salt Salt array of 16 bytes to derive scrypt S salt parameter
     * @param workFactor Work factor to derive scrypt N cost parameter
     * @return Recipient Stanza Cipher Key for decrypting File Key
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    CipherKey getWrapKey(byte[] salt, int workFactor) throws GeneralSecurityException;
}
