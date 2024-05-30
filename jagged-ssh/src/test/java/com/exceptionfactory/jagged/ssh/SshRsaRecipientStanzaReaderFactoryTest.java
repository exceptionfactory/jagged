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

import com.exceptionfactory.jagged.RecipientStanzaReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SshRsaRecipientStanzaReaderFactoryTest {
    private static RSAPrivateCrtKey rsaPrivateKey;

    @BeforeAll
    static void setRsaPrivateKey() throws NoSuchAlgorithmException {
        rsaPrivateKey = RsaKeyPairProvider.getRsaPrivateCrtKey();
    }

    @Test
    void testNewRecipientStanzaReader() throws GeneralSecurityException {
        final RecipientStanzaReader reader = SshRsaRecipientStanzaReaderFactory.newRecipientStanzaReader(rsaPrivateKey);

        assertNotNull(reader);
    }
}
