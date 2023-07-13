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
package com.exceptionfactory.jagged.scrypt;

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ScryptRecipientStanzaWriterFactoryTest {
    private static final byte[] PASSPHRASE = String.class.getName().getBytes(StandardCharsets.UTF_8);

    private static final int WORK_FACTOR = 14;

    @Test
    void testNewRecipientStanzaWriter() {
        final RecipientStanzaWriter recipientStanzaWriter = ScryptRecipientStanzaWriterFactory.newRecipientStanzaWriter(PASSPHRASE, WORK_FACTOR);

        assertNotNull(recipientStanzaWriter);
    }
}
