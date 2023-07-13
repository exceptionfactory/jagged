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
import static org.junit.jupiter.api.Assertions.assertNotNull;

class StandardHeaderKeyProducerTest {
    static final byte[] FILE_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    static final byte[] HEADER_KEY = new byte[]{
            50, 103, -85, -117, 80, 49, -69, -100,
            36, -42, 85, 10, -66, -104, 100, 80,
            90, 31, -92, -51, 54, -3, -4, -83,
            8, -114, -5, 52, 124, -41, 52, 28
    };

    @Test
    void testGetHeaderKey() throws GeneralSecurityException {
        final FileKey fileKey = new FileKey(FILE_KEY);

        final StandardHeaderKeyProducer producer = new StandardHeaderKeyProducer();

        final MacKey headerKey = producer.getHeaderKey(fileKey);

        assertNotNull(headerKey);
        assertArrayEquals(HEADER_KEY, headerKey.getEncoded());
    }
}
