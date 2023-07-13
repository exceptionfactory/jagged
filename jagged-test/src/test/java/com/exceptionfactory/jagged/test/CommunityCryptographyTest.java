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
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.framework.stream.StandardDecryptingChannelFactory;
import com.exceptionfactory.jagged.framework.armor.ArmoredReadableByteChannel;
import com.exceptionfactory.jagged.scrypt.ScryptRecipientStanzaReaderFactory;
import com.exceptionfactory.jagged.x25519.X25519RecipientStanzaReaderFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.exceptionfactory.jagged.test.CommunityCryptographyProperty.IDENTITY;
import static com.exceptionfactory.jagged.test.CommunityCryptographyProperty.PASSPHRASE;
import static com.exceptionfactory.jagged.test.CommunityCryptographyProperty.PAYLOAD;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CommunityCryptographyTest {

    private static final String TESTDATA_PATH = "/CCTV/CCTV-main/age/testdata/";

    private static final String PROPERTY_VALUE_SEPARATOR = ": ";

    private static final int LINE_FEED = 10;

    private static final String DIGEST_ALGORITHM = "SHA-256";

    private static final String ARMORED_YES = "yes";

    private static final String BYTE_HEXADECIMAL_FORMAT = "%02x";

    private static final int BUFFER_SIZE = 8192;

    private static final int END_OF_FILE = -1;

    @TestFactory
    Stream<DynamicTest> testVectors() throws URISyntaxException, IOException {
        final List<Path> testdataFileNames = getTestdataFileNames();
        return testdataFileNames.stream()
                .map(testdataPath ->
                        DynamicTest.dynamicTest(testdataPath.getFileName().toString(), () -> processVector(testdataPath))
                );
    }

    private void processVector(final Path fileName) throws Exception {
        final Path testdataPath = getTestdataPath();
        final Path testdataFilePath = testdataPath.resolve(fileName);
        final InputStream inputStream = Files.newInputStream(testdataFilePath);
        final Map<String, String> properties = readProperties(inputStream);

        final DecryptingChannelFactory decryptingChannelFactory = new StandardDecryptingChannelFactory();
        final RecipientStanzaReader recipientStanzaReader = getRecipientStanzaReader(properties);
        final Iterable<RecipientStanzaReader> recipientStanzaReaders = Collections.singletonList(recipientStanzaReader);
        final ReadableByteChannel inputChannel = Channels.newChannel(inputStream);

        final String expected = properties.get(CommunityCryptographyProperty.EXPECT.getProperty());
        final String armored = properties.get(CommunityCryptographyProperty.ARMORED.getProperty());

        if (CommunityCryptographyExpectation.SUCCESS.getLabel().contentEquals(expected)) {
            final ReadableByteChannel encryptedChannel = getEncryptedChannel(inputChannel, armored);
            final ReadableByteChannel decryptingChannel = decryptingChannelFactory.newDecryptingChannel(encryptedChannel, recipientStanzaReaders);
            assertPayloadExpected(fileName, decryptingChannel, properties);
        } else {
            final Exception exception = assertThrows(Exception.class, () -> {
                final ReadableByteChannel encryptedChannel = getEncryptedChannel(inputChannel, armored);
                final ReadableByteChannel decryptingChannel = decryptingChannelFactory.newDecryptingChannel(encryptedChannel, recipientStanzaReaders);
                getDigestEncoded(decryptingChannel);
            }, fileName.toString());
            assertExceptionExpected(exception, expected);
        }
    }

    private ReadableByteChannel getEncryptedChannel(final ReadableByteChannel inputChannel, final String armored) throws IOException {
        return ARMORED_YES.equals(armored) ? new ArmoredReadableByteChannel(inputChannel) : inputChannel;
    }

    private void assertExceptionExpected(final Exception exception, final String expected) {
        final Class<? extends Exception> exceptionClass = Arrays.stream(CommunityCryptographyExpectation.values())
                .filter(expectation -> expectation.getLabel().equals(expected))
                .map(CommunityCryptographyExpectation::getExceptionClass)
                .findFirst()
                .orElseThrow(IllegalArgumentException::new);

        assertInstanceOf(exceptionClass, exception, exception.toString());
    }

    private void assertPayloadExpected(final Path fileName, final ReadableByteChannel decryptingChannel, final Map<String, String> properties) throws IOException, NoSuchAlgorithmException {
        final String digestedPayload = getDigestEncoded(decryptingChannel);
        final String expectedPayload = properties.get(PAYLOAD.getProperty());
        assertEquals(expectedPayload, digestedPayload, fileName.toString());
    }

    private RecipientStanzaReader getRecipientStanzaReader(final Map<String, String> properties) throws GeneralSecurityException {
        final String identity = properties.get(IDENTITY.getProperty());

        final RecipientStanzaReader recipientStanzaReader;
        if (identity == null) {
            final String passphrase = properties.get(PASSPHRASE.getProperty());
            final byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            recipientStanzaReader = ScryptRecipientStanzaReaderFactory.newRecipientStanzaReader(passphraseBytes);
        } else {
            recipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(identity);
        }

        return recipientStanzaReader;
    }

    private String getDigestEncoded(final ReadableByteChannel decryptingChannel) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        while (buffer.hasRemaining()) {
            decryptingChannel.read(buffer);
            buffer.flip();
            if (buffer.hasRemaining()) {
                messageDigest.update(buffer);
                buffer.flip();
            }
        }

        final byte[] digest = messageDigest.digest();
        final StringBuilder builder = new StringBuilder();

        for (final byte digestByte : digest) {
            final String hexadecimal = String.format(BYTE_HEXADECIMAL_FORMAT, digestByte);
            builder.append(hexadecimal);
        }

        return builder.toString();
    }

    private Map<String, String> readProperties(final InputStream inputStream) throws IOException {
        final Map<String, String> properties = new LinkedHashMap<>();

        StringBuilder builder = new StringBuilder();
        int read = inputStream.read();
        while (read != END_OF_FILE) {
            if (read == LINE_FEED) {
                final String[] line = builder.toString().split(PROPERTY_VALUE_SEPARATOR);
                final String property = line[0];
                final String value = line[1];
                properties.put(property, value);
                builder = new StringBuilder();

                final int nextRead = inputStream.read();
                if (nextRead == LINE_FEED) {
                    break;
                }
                read = nextRead;
            } else {
                builder.append((char) read);
                read = inputStream.read();
            }
        }
        return properties;
    }

    private List<Path> getTestdataFileNames() throws URISyntaxException, IOException {
        final Path testdataPath = getTestdataPath();

        final List<Path> fileNames = new ArrayList<>();
        try (DirectoryStream<Path> filePaths = Files.newDirectoryStream(testdataPath)) {
            for (final Path filePath : filePaths) {
                final Path fileName = filePath.getFileName();
                fileNames.add(fileName);
            }
        }

        Collections.sort(fileNames);
        return fileNames;
    }

    private Path getTestdataPath() throws URISyntaxException {
        final URL testdataUrl = CommunityCryptographyTest.class.getResource(TESTDATA_PATH);
        if (testdataUrl == null) {
            throw new IllegalStateException(String.format("Resource not found [%s]", TESTDATA_PATH));
        }
        final URI testdataUri = testdataUrl.toURI();
        return Paths.get(testdataUri);
    }
}
