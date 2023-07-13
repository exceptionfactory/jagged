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

/**
 * Message Authentication Code Key extension of Cryptographic Algorithm Key using HmacSHA256
 */
public class MacKey extends CryptographicAlgorithmKey {
    /**
     * Message Authentication Code Key constructor with required symmetric key
     *
     * @param key Symmetric Key with byte length based on Cryptographic Key Type
     * @param cryptographicKeyType Cryptographic Key Type
     */
    MacKey(final byte[] key, final CryptographicKeyType cryptographicKeyType) {
        super(key, cryptographicKeyType, CryptographicAlgorithm.HMACSHA256);
    }
}
