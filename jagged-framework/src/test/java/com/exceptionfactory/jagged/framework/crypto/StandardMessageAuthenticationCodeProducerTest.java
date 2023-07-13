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

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class StandardMessageAuthenticationCodeProducerTest {
    static final byte[] INPUT = new byte[]{0, 1, 2, 3};

    static final byte[] EXPECTED_OUTPUT = new byte[]{
            -70, 108, -59, 94, 32, 29, 24, 57,
            18, -109, -115, 55, -64, -37, 70, -112,
            -16, 5, -115, -73, 109, 76, -4, 51,
            -39, -103, 92, 17, -30, -26, -10, -70
    };

    @Test
    void testGetMessageAuthenticationCode() throws GeneralSecurityException {
        final MacKey macKey = new MacKey(MacKeyTest.SYMMETRIC_KEY, CryptographicKeyType.EXTRACTED_KEY);
        final StandardMessageAuthenticationCodeProducer producer = new StandardMessageAuthenticationCodeProducer(macKey);

        final ByteBuffer inputBuffer = ByteBuffer.wrap(INPUT);
        final byte[] messageAuthenticationCode = producer.getMessageAuthenticationCode(inputBuffer);

        assertArrayEquals(EXPECTED_OUTPUT, messageAuthenticationCode);
    }
}
