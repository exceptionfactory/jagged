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
package com.exceptionfactory.jagged.framework.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StandardEncryptingChannelFactoryTest {
    private static final String ALGORITHM_FILTER = "Cipher.ChaCha20-Poly1305";

    private StandardEncryptingChannelFactory factory;

    @BeforeEach
    void setFactory() {
        factory = new StandardEncryptingChannelFactory();
    }

    @Test
    void testNewEncryptingChannel() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final WritableByteChannel encryptingChannel = factory.newEncryptingChannel(outputChannel, Collections.emptyList());
        assertNotNull(encryptingChannel);
    }

    @Test
    void testNewEncryptingChannelWithProvider() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final Provider provider = getProvider();
        final StandardEncryptingChannelFactory channelFactory = new StandardEncryptingChannelFactory(provider);
        final WritableByteChannel encryptingChannel = channelFactory.newEncryptingChannel(outputChannel, Collections.emptyList());
        assertNotNull(encryptingChannel);
    }

    @Test
    void testNewEncryptingChannelClosed() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);
        outputChannel.close();

        assertThrows(ClosedChannelException.class, () -> factory.newEncryptingChannel(outputChannel, Collections.emptyList()));
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
