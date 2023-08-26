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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PayloadIvParameterSpecTest {
    private static final int EXPECTED_LENGTH = 12;

    private static final int INCREMENTS = 1024;

    private static final byte INCREMENT_COUNTER = 4;

    private static final int INCREMENT_COUNTER_INDEX = 9;

    private static final int LAST_CHUNK_FLAG_INDEX = 11;

    private static final byte LAST_CHUNK_FLAG = 1;

    private static final byte[] MAXIMUM_INITIALIZATION_VECTOR = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0};

    @Test
    void testGetInitializationVector() {
        final PayloadIvParameterSpec parameterSpec = new PayloadIvParameterSpec();

        final byte[] initializationVector = parameterSpec.getIV();
        assertEquals(EXPECTED_LENGTH, initializationVector.length);
        assertFalse(parameterSpec.isNotFirstChunk());
    }

    @Test
    void testSetLastChunkFlag() {
        final PayloadIvParameterSpec parameterSpec = new PayloadIvParameterSpec();

        final byte[] firstInitializationVector = parameterSpec.getIV();
        parameterSpec.setLastChunkFlag();
        final byte[] initializationVector = parameterSpec.getIV();

        final byte[] expectedInitializationVector = firstInitializationVector.clone();
        expectedInitializationVector[LAST_CHUNK_FLAG_INDEX] = LAST_CHUNK_FLAG;

        assertArrayEquals(expectedInitializationVector, initializationVector);
    }

    @Test
    void testIncrementInitializationVector() {
        final PayloadIvParameterSpec parameterSpec = new PayloadIvParameterSpec();

        final byte[] firstInitializationVector = parameterSpec.getIV();

        for (int i = 0; i < INCREMENTS; i++) {
            parameterSpec.incrementInitializationVector();
        }

        assertTrue(parameterSpec.isNotFirstChunk());
        final byte[] lastInitializationVector = parameterSpec.getIV();

        final byte[] expectedInitializationVector = firstInitializationVector.clone();
        expectedInitializationVector[INCREMENT_COUNTER_INDEX] = INCREMENT_COUNTER;
        assertArrayEquals(expectedInitializationVector, lastInitializationVector);
    }

    @Test
    void testIncrementInitializationVectorMaximum() {
        final PayloadIvParameterSpec parameterSpec = new PayloadIvParameterSpec(MAXIMUM_INITIALIZATION_VECTOR);

        assertThrows(IllegalStateException.class, parameterSpec::incrementInitializationVector);
    }

    @Test
    void testInitializationVectorNotFound() {
        assertThrows(IllegalArgumentException.class, () -> new PayloadIvParameterSpec(null));
    }

    @Test
    void testInitializationVectorLengthNotValid() {
        assertThrows(IllegalArgumentException.class, () -> new PayloadIvParameterSpec(new byte[]{}));
    }
}
