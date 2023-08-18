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
package com.exceptionfactory.jagged.framework.armor;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;

class ArmoredDecryptingChannelFactoryTest {
    private static final String ALGORITHM_FILTER = "Cipher.ChaCha20-Poly1305";

    private static final byte[] BUFFER = new byte[]{0};

    @Test
    void testNewDecryptingChannelException() {
        final ArmoredDecryptingChannelFactory factory = new ArmoredDecryptingChannelFactory();

        assertThrowsException(factory);
    }

    @Test
    void testNewDecryptingChannelWithProviderException() {
        final Provider provider = getProvider();
        final ArmoredDecryptingChannelFactory factory = new ArmoredDecryptingChannelFactory(provider);

        assertThrowsException(factory);
    }

    private void assertThrowsException(final ArmoredDecryptingChannelFactory factory) {
        final ReadableByteChannel inputChannel = Channels.newChannel(new ByteArrayInputStream(BUFFER));
        assertThrows(IOException.class, () -> factory.newDecryptingChannel(inputChannel, Collections.emptyList()));
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
