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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BasePointPublicKeyTest {
    private static final int BASE_POINT = 9;

    private static final String FORMAT = "RAW";

    @Test
    void testGetAlgorithm() {
        final BasePointPublicKey basePointPublicKey = new BasePointPublicKey();

        assertEquals(RecipientIndicator.KEY_ALGORITHM.getIndicator(), basePointPublicKey.getAlgorithm());
    }

    @Test
    void testGetFormat() {
        final BasePointPublicKey basePointPublicKey = new BasePointPublicKey();

        assertEquals(FORMAT, basePointPublicKey.getFormat());
    }

    @Test
    void testGetEncoded() {
        final BasePointPublicKey basePointPublicKey = new BasePointPublicKey();

        final byte[] encoded = basePointPublicKey.getEncoded();
        assertEquals(RecipientKeyType.X25519.getKeyLength(), encoded.length);
        assertEquals(BASE_POINT, encoded[0]);
    }
}
