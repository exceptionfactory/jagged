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

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Hashed Derived Key Producer using HMAC-based Extract-and-Expand Key Derivation Function described in RFC 5869
 */
public class HashedDerivedKeyProducer {
    private static final byte FIRST_ITERATION = 1;

    /**
     * Get Derived Key using HKDF-SHA-256 extracted and expanded from input key
     *
     * @param inputKey Input Key Material
     * @param saltKey Salt Key with encoded byte array
     * @param info Application Information
     * @return Key derived from RFC 5869 Sections 2.2 and 2.3 extract and expand
     * @throws GeneralSecurityException Thrown on key derivation processing failures
     */
    protected byte[] getDerivedKey(final SecretKey inputKey, final MacKey saltKey, final byte[] info) throws GeneralSecurityException {
        final MacKey extractedKey = getExtractedKey(inputKey, saltKey);
        return getExpandedKey(extractedKey, info);
    }

    /**
     * Get extracted key as described in RFC 5869 Section 2.2 with HMAC-SHA-256 Pseudo Random Function
     *
     * @param inputKey Input Key Material
     * @param saltKey Salt Key containing encoded byte array
     * @return Extracted Message Authentication Code Key
     * @throws GeneralSecurityException Thrown on failures to create MAC Producer
     */
    private MacKey getExtractedKey(final SecretKey inputKey, final MacKey saltKey) throws GeneralSecurityException {
        final MessageAuthenticationCodeProducer producer = MessageAuthenticationCodeProducerFactory.newMessageAuthenticationCodeProducer(saltKey);
        final ByteBuffer inputKeyEncoded = ByteBuffer.wrap(inputKey.getEncoded());
        final byte[] extracted = producer.getMessageAuthenticationCode(inputKeyEncoded);
        return new MacKey(extracted, CryptographicKeyType.EXTRACTED_KEY);
    }

    /**
     * Get expanded key as described in RFC 5869 Section 2.3 with HMAC-SHA-256 Pseudo Random Function
     *
     * @param extractedKey Extracted Key
     * @param info Application Information
     * @return Expanded Key of 32 bytes based on HMAC-SHA-256
     * @throws GeneralSecurityException Thrown on failures to create MAC Producer
     */
    private byte[] getExpandedKey(final MacKey extractedKey, final byte[] info) throws GeneralSecurityException {
        final MessageAuthenticationCodeProducer producer = MessageAuthenticationCodeProducerFactory.newMessageAuthenticationCodeProducer(extractedKey);
        final ByteBuffer infoFirstIterationEncoded = getInfoFirstIterationEncoded(info);
        return producer.getMessageAuthenticationCode(infoFirstIterationEncoded);
    }

    /**
     * Get Application Information concatenated with 0x01 as described in the first iteration of HKDF Expand
     *
     * @param info Application Information
     * @return Application Information concatenated with 0x01
     */
    private ByteBuffer getInfoFirstIterationEncoded(final byte[] info) {
        final int encodedLength = info.length + FIRST_ITERATION;
        final ByteBuffer encoded = ByteBuffer.allocate(encodedLength);
        encoded.put(info);
        encoded.put(FIRST_ITERATION);
        encoded.flip();
        return encoded;
    }
}
