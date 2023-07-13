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
import java.util.Objects;

/**
 * Standard implementation of Payload Key Producer using HMAC-based Extract-and-Expand Key Derivation Function described in RFC 5869
 */
class StandardPayloadKeyProducer extends HashedDerivedKeyProducer implements PayloadKeyProducer {
    /** Payload Application Information for HKDF-SHA-256 as described in age-encryption Header MAC key derivation */
    private static final byte[] PAYLOAD_INFO = new byte[]{'p', 'a', 'y', 'l', 'o', 'a', 'd'};

    /**
     * Get Payload Key using HKDF-SHA-256
     *
     * @param fileKey File Key
     * @param payloadNonceKey Payload Nonce Key
     * @return Payload Cipher Key
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    @Override
    public CipherKey getPayloadKey(final FileKey fileKey, final PayloadNonceKey payloadNonceKey) throws GeneralSecurityException {
        Objects.requireNonNull(fileKey, "File Key required");
        Objects.requireNonNull(payloadNonceKey, "Payload Nonce Key required");
        final byte[] payloadKey = getDerivedKey(fileKey, payloadNonceKey, PAYLOAD_INFO);
        return new CipherKey(payloadKey);
    }
}
