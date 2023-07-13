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
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class StandardPayloadKeyProducerTest {
    static final byte[] FILE_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    static final byte[] PAYLOAD_NONCE_KEY = new byte[]{
            8, 7, 6, 5, 4, 3, 2, 1,
            8, 7, 6, 5, 4, 3, 2, 1
    };

    static final byte[] PAYLOAD_KEY = new byte[]{
            -54, -21, -57, 44, -71, 0, -70, 72,
            70, 24, -119, -71, -18, -8, -92, 110,
            26, 22, 10, -6, -82, 12, 16, -91,
            -28, 93, 8, 89, -62, 122, 117, -90
    };

    @Test
    void testGetPayloadKey() throws GeneralSecurityException {
        final StandardPayloadKeyProducer producer = new StandardPayloadKeyProducer();

        final FileKey fileKey = new FileKey(FILE_KEY);
        final PayloadNonceKey payloadNonce = new PayloadNonceKey(PAYLOAD_NONCE_KEY);

        final CipherKey payloadKey = producer.getPayloadKey(fileKey, payloadNonce);

        assertArrayEquals(PAYLOAD_KEY, payloadKey.getEncoded());
    }
}
