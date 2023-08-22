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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CipherKeyTest {
    static final byte[] SYMMETRIC_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final byte[] INVALID_KEY = new byte[0];

    @Test
    void testCipherKey() {
        final CipherKey cipherKey = new CipherKey(SYMMETRIC_KEY);

        assertEquals(CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm(), cipherKey.getAlgorithm());
        assertArrayEquals(SYMMETRIC_KEY, cipherKey.getEncoded());
        assertNotNull(cipherKey.getFormat());
        assertFalse(cipherKey.isDestroyed());
    }

    @Test
    void testDestroy() {
        final byte[] cloned = SYMMETRIC_KEY.clone();
        final CipherKey cipherKey = new CipherKey(cloned);

        assertFalse(cipherKey.isDestroyed());
        cipherKey.destroy();
        assertTrue(cipherKey.isDestroyed());
    }

    @Test
    void testCipherKeyLengthNotValid() {
        assertThrows(IllegalArgumentException.class, () -> new CipherKey(INVALID_KEY));
    }
}
