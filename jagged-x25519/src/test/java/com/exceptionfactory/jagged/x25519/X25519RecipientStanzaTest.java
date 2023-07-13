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

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class X25519RecipientStanzaTest {
    private static final byte[] BODY = new byte[]{};

    private static final String EPHEMERAL_SHARE = String.class.getSimpleName();

    @Test
    void testGetType() {
        final X25519RecipientStanza recipientStanza = new X25519RecipientStanza(EPHEMERAL_SHARE, BODY);

        assertEquals(RecipientIndicator.STANZA_TYPE.getIndicator(), recipientStanza.getType());
    }

    @Test
    void testGetArguments() {
        final X25519RecipientStanza recipientStanza = new X25519RecipientStanza(EPHEMERAL_SHARE, BODY);

        assertEquals(Collections.singletonList(EPHEMERAL_SHARE), recipientStanza.getArguments());
    }

    @Test
    void testGetBody() {
        final X25519RecipientStanza recipientStanza = new X25519RecipientStanza(EPHEMERAL_SHARE, BODY);

        assertArrayEquals(BODY, recipientStanza.getBody());
    }
}
