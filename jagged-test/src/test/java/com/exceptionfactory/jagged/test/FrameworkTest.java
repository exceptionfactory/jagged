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
package com.exceptionfactory.jagged.test;

import com.exceptionfactory.jagged.DecryptingChannelFactory;
import com.exceptionfactory.jagged.EncryptingChannelFactory;
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.armor.ArmoredDecryptingChannelFactory;
import com.exceptionfactory.jagged.framework.armor.ArmoredEncryptingChannelFactory;
import com.exceptionfactory.jagged.framework.stream.StandardDecryptingChannelFactory;
import com.exceptionfactory.jagged.framework.stream.StandardEncryptingChannelFactory;
import com.exceptionfactory.jagged.scrypt.ScryptRecipientStanzaReaderFactory;
import com.exceptionfactory.jagged.scrypt.ScryptRecipientStanzaWriterFactory;
import com.exceptionfactory.jagged.x25519.X25519KeyPairGenerator;
import com.exceptionfactory.jagged.x25519.X25519RecipientStanzaReaderFactory;
import com.exceptionfactory.jagged.x25519.X25519RecipientStanzaWriterFactory;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class FrameworkTest {
    private static final String CONTENT = FrameworkTest.class.getName();

    private static final byte[] CONTENT_BINARY = CONTENT.getBytes(StandardCharsets.UTF_8);

    private static final int PLAIN_CHUNK_SIZE = 65536;

    private static final byte PLAIN_BYTE = 7;

    private static final byte[] PASSPHRASE = FrameworkTest.class.getSimpleName().getBytes(StandardCharsets.UTF_8);

    private static final int WORK_FACTOR = 14;

    @Test
    void testScryptBinary() throws GeneralSecurityException, IOException {
        final RecipientStanzaWriter recipientStanzaWriter = ScryptRecipientStanzaWriterFactory.newRecipientStanzaWriter(PASSPHRASE, WORK_FACTOR);
        final byte[] encrypted = getEncrypted(CONTENT_BINARY, recipientStanzaWriter, new StandardEncryptingChannelFactory());

        final RecipientStanzaReader recipientStanzaReader = ScryptRecipientStanzaReaderFactory.newRecipientStanzaReader(PASSPHRASE);
        final byte[] decrypted = getDecrypted(CONTENT_BINARY.length, recipientStanzaReader, encrypted, new StandardDecryptingChannelFactory());

        assertArrayEquals(CONTENT_BINARY, decrypted);
    }

    @Test
    void testX25519Armored() throws GeneralSecurityException, IOException {
        final KeyPair keyPair = generateKeyPair();

        final String publicKeyEncoded = keyPair.getPublic().toString();
        final RecipientStanzaWriter recipientStanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(publicKeyEncoded);
        final byte[] encrypted = getEncrypted(CONTENT_BINARY, recipientStanzaWriter, new ArmoredEncryptingChannelFactory());

        final String privateKeyEncoded = keyPair.getPrivate().toString();
        final RecipientStanzaReader recipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(privateKeyEncoded);
        final byte[] decrypted = getDecrypted(CONTENT_BINARY.length, recipientStanzaReader, encrypted, new ArmoredDecryptingChannelFactory());

        assertArrayEquals(CONTENT_BINARY, decrypted);
    }

    @Test
    void testX25519ArmoredChunk() throws GeneralSecurityException, IOException {
        final KeyPair keyPair = generateKeyPair();

        final String publicKeyEncoded = keyPair.getPublic().toString();
        final RecipientStanzaWriter recipientStanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(publicKeyEncoded);

        final byte[] contentBinary = new byte[PLAIN_CHUNK_SIZE];
        Arrays.fill(contentBinary, PLAIN_BYTE);

        final byte[] encrypted = getEncrypted(contentBinary, recipientStanzaWriter, new ArmoredEncryptingChannelFactory());

        final String privateKeyEncoded = keyPair.getPrivate().toString();
        final RecipientStanzaReader recipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(privateKeyEncoded);
        final byte[] decrypted = getDecrypted(PLAIN_CHUNK_SIZE, recipientStanzaReader, encrypted, new ArmoredDecryptingChannelFactory());

        assertArrayEquals(contentBinary, decrypted);
    }

    @Test
    void testX25519Binary() throws GeneralSecurityException, IOException {
        final KeyPair keyPair = generateKeyPair();

        final String publicKeyEncoded = keyPair.getPublic().toString();
        final RecipientStanzaWriter recipientStanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(publicKeyEncoded);
        final byte[] encrypted = getEncrypted(CONTENT_BINARY, recipientStanzaWriter, new StandardEncryptingChannelFactory());

        final String privateKeyEncoded = keyPair.getPrivate().toString();
        final RecipientStanzaReader recipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(privateKeyEncoded);
        final byte[] decrypted = getDecrypted(CONTENT_BINARY.length, recipientStanzaReader, encrypted, new StandardDecryptingChannelFactory());

        assertArrayEquals(CONTENT_BINARY, decrypted);
    }

    @Test
    void testX25519BinaryChunk() throws GeneralSecurityException, IOException {
        final KeyPair keyPair = generateKeyPair();

        final String publicKeyEncoded = keyPair.getPublic().toString();
        final RecipientStanzaWriter recipientStanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(publicKeyEncoded);

        final byte[] contentBinary = new byte[PLAIN_CHUNK_SIZE];
        Arrays.fill(contentBinary, PLAIN_BYTE);

        final byte[] encrypted = getEncrypted(contentBinary, recipientStanzaWriter, new StandardEncryptingChannelFactory());

        final String privateKeyEncoded = keyPair.getPrivate().toString();
        final RecipientStanzaReader recipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(privateKeyEncoded);
        final byte[] decrypted = getDecrypted(PLAIN_CHUNK_SIZE, recipientStanzaReader, encrypted, new StandardDecryptingChannelFactory());

        assertArrayEquals(contentBinary, decrypted);
    }

    @Test
    void testX25519BinarySingleRecipientMultiplePrivateKeys() throws GeneralSecurityException, IOException {
        final KeyPair keyPair = generateKeyPair();
        final KeyPair secondKeyPair = generateKeyPair();

        final String publicKeyEncoded = keyPair.getPublic().toString();
        final RecipientStanzaWriter recipientStanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(publicKeyEncoded);
        final byte[] encrypted = getEncrypted(CONTENT_BINARY, recipientStanzaWriter, new StandardEncryptingChannelFactory());

        final String privateKeyEncoded = keyPair.getPrivate().toString();
        final RecipientStanzaReader recipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(privateKeyEncoded);

        final String secondPrivateKeyEncoded = secondKeyPair.getPrivate().toString();
        final RecipientStanzaReader secondRecipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(secondPrivateKeyEncoded);

        final List<RecipientStanzaReader> recipientStanzaReaders = Arrays.asList(recipientStanzaReader, secondRecipientStanzaReader);
        final byte[] decrypted = getDecrypted(CONTENT_BINARY.length, recipientStanzaReaders, encrypted, new StandardDecryptingChannelFactory());

        assertArrayEquals(CONTENT_BINARY, decrypted);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator();
        return keyPairGenerator.generateKeyPair();
    }

    private byte[] getEncrypted(
            final byte[] inputBinary,
            final RecipientStanzaWriter recipientStanzaWriter,
            final EncryptingChannelFactory encryptingChannelFactory
    ) throws GeneralSecurityException, IOException {
        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);

        final ByteBuffer contentBuffer = ByteBuffer.wrap(inputBinary);

        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);
        final WritableByteChannel encryptingChannel = encryptingChannelFactory.newEncryptingChannel(outputChannel, recipientStanzaWriters);

        final int encrypted = encryptingChannel.write(contentBuffer);
        encryptingChannel.close();
        assertEquals(inputBinary.length, encrypted);

        return outputStream.toByteArray();
    }

    private byte[] getDecrypted(
            final int decryptedLength,
            final RecipientStanzaReader recipientStanzaReader,
            final byte[] encrypted,
            final DecryptingChannelFactory decryptingChannelFactory
    ) throws GeneralSecurityException, IOException {
        final List<RecipientStanzaReader> recipientStanzaReaders = Collections.singletonList(recipientStanzaReader);
        return getDecrypted(decryptedLength, recipientStanzaReaders, encrypted, decryptingChannelFactory);
    }

    private byte[] getDecrypted(
            final int decryptedLength,
            final List<RecipientStanzaReader> recipientStanzaReaders,
            final byte[] encrypted,
            final DecryptingChannelFactory decryptingChannelFactory
    ) throws GeneralSecurityException, IOException {
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(encrypted);
        final ReadableByteChannel inputChannel = Channels.newChannel(inputStream);
        final ReadableByteChannel decryptingChannel = decryptingChannelFactory.newDecryptingChannel(inputChannel, recipientStanzaReaders);

        final ByteBuffer contentBuffer = ByteBuffer.allocate(decryptedLength);
        while (contentBuffer.hasRemaining()) {
            decryptingChannel.read(contentBuffer);
        }

        decryptingChannel.close();

        return contentBuffer.array();
    }
}
