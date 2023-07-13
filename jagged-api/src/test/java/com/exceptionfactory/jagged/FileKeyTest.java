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
package com.exceptionfactory.jagged;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileKeyTest {
    private static final byte[] FILE_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
    };

    @Test
    void testFileKey() {
        final FileKey fileKey = new FileKey();

        final byte[] encoded = fileKey.getEncoded();
        assertNotNull(encoded);
        assertNotNull(fileKey.getAlgorithm());
        assertNotNull(fileKey.getFormat());
    }

    @Test
    void testFileKeyConstructed() {
        final FileKey fileKey = new FileKey(FILE_KEY);

        final byte[] encoded = fileKey.getEncoded();
        assertArrayEquals(FILE_KEY, encoded);
    }

    @Test
    void testFileKeyDestroyed() {
        final FileKey fileKey = new FileKey(FILE_KEY);

        assertFalse(fileKey.isDestroyed());
        fileKey.destroy();
        assertTrue(fileKey.isDestroyed());
    }

    @Test
    void testFileKeyException() {
        assertThrows(IllegalArgumentException.class, () -> new FileKey(new byte[]{}));
    }
}
