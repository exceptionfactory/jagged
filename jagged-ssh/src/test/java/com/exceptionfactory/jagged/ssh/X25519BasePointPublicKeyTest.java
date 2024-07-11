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
package com.exceptionfactory.jagged.ssh;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class X25519BasePointPublicKeyTest {
    private static final int BASE_POINT = 9;

    private static final String FORMAT = "RAW";

    @Test
    void testGetAlgorithm() {
        final X25519BasePointPublicKey basePointPublicKey = new X25519BasePointPublicKey();

        assertEquals(EllipticCurveKeyType.X25519.getAlgorithm(), basePointPublicKey.getAlgorithm());
    }

    @Test
    void testGetFormat() {
        final X25519BasePointPublicKey basePointPublicKey = new X25519BasePointPublicKey();

        assertEquals(FORMAT, basePointPublicKey.getFormat());
    }

    @Test
    void testGetEncoded() {
        final X25519BasePointPublicKey basePointPublicKey = new X25519BasePointPublicKey();

        final byte[] encoded = basePointPublicKey.getEncoded();
        assertEquals(EllipticCurveKeyType.X25519.getKeyLength(), encoded.length);
        assertEquals(BASE_POINT, encoded[0]);
    }
}
