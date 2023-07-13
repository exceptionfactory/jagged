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
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class X25519SharedWrapKeyProducerTest {

    private static final String RECIPIENT_PUBLIC_KEY_ENCODED = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo";

    private static final String EPHEMERAL_PUBLIC_KEY_ENCODED = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08";

    private static final String SHARED_SECRET_KEY_ENCODED = "Sl2dW6TOLeFyjjv0gDUPJeB+IclH0Z4zdvCbPB4WF0I";

    private static final CanonicalBase64.Decoder DECODER = CanonicalBase64.getDecoder();

    private static final byte[] WRAP_KEY_ENCODED = new byte[]{
            73, -12, 85, -50, -18, -125, -48, 3,
            14, 81, 76, 109, -4, 100, 18, -91,
            -3, 45, 72, 47, -114, -5, -46, 80,
            -111, 85, -83, 103, -76, -33, 82, 13
    };

    private RecipientKeyFactory recipientKeyFactory;

    private X25519SharedWrapKeyProducer producer;

    @BeforeEach
    void setProducer() throws GeneralSecurityException {
        recipientKeyFactory = new StandardRecipientKeyFactory();
        final byte[] recipientPublicKeyEncoded = DECODER.decode(RECIPIENT_PUBLIC_KEY_ENCODED.getBytes(StandardCharsets.US_ASCII));
        final PublicKey recipientPublicKey = recipientKeyFactory.getPublicKey(recipientPublicKeyEncoded);
        producer = new X25519SharedWrapKeyProducer(recipientPublicKey);
    }

    @Test
    void testGetWrapKey() throws GeneralSecurityException {
        final byte[] sharedSecretKeyEncoded = DECODER.decode(SHARED_SECRET_KEY_ENCODED.getBytes(StandardCharsets.US_ASCII));
        final SharedSecretKey sharedSecretKey = new SharedSecretKey(sharedSecretKeyEncoded);

        final byte[] ephemeralPublicKeyEncoded = DECODER.decode(EPHEMERAL_PUBLIC_KEY_ENCODED.getBytes(StandardCharsets.US_ASCII));
        final PublicKey ephemeralPublicKey = recipientKeyFactory.getPublicKey(ephemeralPublicKeyEncoded);

        final CipherKey wrapKey = producer.getWrapKey(sharedSecretKey, ephemeralPublicKey);

        assertNotNull(wrapKey);
        assertArrayEquals(WRAP_KEY_ENCODED, wrapKey.getEncoded());
    }
}
