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

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class MessageAuthenticationCodeProducerFactoryTest {

    @Test
    void testNewByteBufferDecryptor() throws GeneralSecurityException {
        final MacKey macKey = new MacKey(MacKeyTest.SYMMETRIC_KEY, CryptographicKeyType.EXTRACTED_KEY);

        final MessageAuthenticationCodeProducer messageAuthenticationCodeProducer = MessageAuthenticationCodeProducerFactory.newMessageAuthenticationCodeProducer(macKey);

        assertNotNull(messageAuthenticationCodeProducer);
    }
}
