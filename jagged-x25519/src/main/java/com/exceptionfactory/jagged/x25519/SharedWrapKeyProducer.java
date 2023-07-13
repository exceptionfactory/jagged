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

import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Abstraction for producing Wrap Key from Shared Secret Key using HMAC-based Extract-and-Expand Key Derivation Function described in RFC 5869
 */
interface SharedWrapKeyProducer {
    /**
     * Get Wrap Key using shared secret key and ephemeral public key
     *
     * @param sharedSecretKey Shared Secret Key
     * @param ephemeralPublicKey Ephemeral Public Key decoded from Recipient Stanza Arguments
     * @return Recipient Stanza Cipher Key for decrypting File Key
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    CipherKey getWrapKey(SharedSecretKey sharedSecretKey, PublicKey ephemeralPublicKey) throws GeneralSecurityException;
}
