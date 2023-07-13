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

import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.framework.format.HeaderDecodingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ReadableByteChannel;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class StandardDecryptionChannelFactoryTest {
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[]{};

    @Mock
    private RecipientStanzaReader recipientStanzaReader;

    private StandardDecryptingChannelFactory factory;

    @BeforeEach
    void setFactory() {
        factory = new StandardDecryptingChannelFactory();
    }

    @Test
    void testNewDecryptingChannelClosedException() throws IOException {
        final ReadableByteChannel inputChannel = getInputChannel();
        inputChannel.close();

        assertThrows(ClosedChannelException.class, () -> factory.newDecryptingChannel(inputChannel, Collections.singletonList(recipientStanzaReader)));
    }

    @Test
    void testNewDecryptingChannelReadException() {
        final ReadableByteChannel inputChannel = getInputChannel();

        assertThrows(HeaderDecodingException.class, () -> factory.newDecryptingChannel(inputChannel, Collections.singletonList(recipientStanzaReader)));
    }

    private ReadableByteChannel getInputChannel() {
        return Channels.newChannel(new ByteArrayInputStream(EMPTY_BYTE_ARRAY));
    }
}
