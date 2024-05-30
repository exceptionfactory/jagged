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

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SshRsaRecipientStanzaWriterFactoryTest {
    private static RSAPublicKey rsaPublicKey;

    @BeforeAll
    static void setRsaPublicKey() throws NoSuchAlgorithmException {
        rsaPublicKey = RsaKeyPairProvider.getRsaPublicKey();
    }

    @Test
    void testNewRecipientStanzaWriter() {
        final RecipientStanzaWriter writer = SshRsaRecipientStanzaWriterFactory.newRecipientStanzaWriter(rsaPublicKey);

        assertNotNull(writer);
    }
}
