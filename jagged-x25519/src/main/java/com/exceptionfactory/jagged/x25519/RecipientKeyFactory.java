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
package com.exceptionfactory.jagged.x25519;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Abstraction for producing Java Cryptography Public Key and Private Key objects from binary representations
 */
interface RecipientKeyFactory {
    /**
     * Get Public Key from encoded binary
     *
     * @param publicKeyEncoded Encoded public key
     * @return Public Key
     * @throws GeneralSecurityException Thrown on key processing failures
     */
    PublicKey getPublicKey(byte[] publicKeyEncoded) throws GeneralSecurityException;

    /**
     * Get Private Key from encoded binary
     *
     * @param privateKeyEncoded Encoded private key
     * @return Private Key
     * @throws GeneralSecurityException Thrown on key processing failures
     */
    PrivateKey getPrivateKey(byte[] privateKeyEncoded) throws GeneralSecurityException;
}
