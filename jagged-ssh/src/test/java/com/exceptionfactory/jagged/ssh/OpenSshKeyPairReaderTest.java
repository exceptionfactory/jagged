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

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenSshKeyPairReaderTest {
    private static final String RSA_ALGORITHM = "RSA";

    private static final String INVALID_CIPHER = "CIPHER";

    private static final int INVALID_KEY_COUNT = 2;

    private static final int VALID_KEY_COUNT = 1;

    private static final byte VALID_PADDING = 1;

    private static final byte INVALID_PADDING = 2;

    private static final String INVALID_KEY_TYPE = "ssh-invalid";

    private static final int BUFFER_SIZE = 4096;

    private static final int CHECK_NUMBER = 1234;

    private static final String KDF_TYPE_NONE = "none";

    private static final byte[] EMPTY_BLOCK = new byte[]{};

    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private final OpenSshKeyPairReader reader = new OpenSshKeyPairReader();

    @Test
    void testReadHeaderNotFound() {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(0);

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadBlockLengthInvalid() {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);

        inputBuffer.putInt(Integer.MAX_VALUE);
        inputBuffer.flip();

        assertThrows(InvalidKeyException.class, () -> reader.readBlock(inputBuffer));
    }

    @Test
    void testReadBodyLineFeedNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());

        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadHeaderNotMatched() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.FOOTER.getIndicator());
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadHeaderWithoutLineEnd() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(OpenSshKeyIndicator.FOOTER.getIndicator());
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadHeaderCarriageReturnWithoutLineFeed() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());
        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(Byte.toString(KeySeparator.LINE_FEED.getCode())));
    }

    @Test
    void testReadHeaderFooterNotMatched() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());
        outputStream.write(KeySeparator.LINE_FEED.getCode());

        final byte[] footer = new byte[OpenSshKeyIndicator.FOOTER.getLength()];
        outputStream.write(footer);

        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());
        outputStream.write(KeySeparator.LINE_FEED.getCode());

        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadHeaderEmptyBodyFooter() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());
        outputStream.write(KeySeparator.LINE_FEED.getCode());

        outputStream.write(OpenSshKeyIndicator.FOOTER.getIndicator());
        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadMagicHeaderInvalidFooter() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());

        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));
        final byte[] magicHeader = new byte[OpenSshKeyIndicator.MAGIC_HEADER.getLength()];
        outputStream.write(ENCODER.encode(magicHeader));
        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());
        outputStream.write(KeySeparator.CARRIAGE_RETURN.getCode());

        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(UnrecoverableKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadFooterNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());

        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadMagicNotMatched() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());

        final byte[] emptyHeader = new byte[OpenSshKeyIndicator.MAGIC_HEADER.getLength()];
        outputStream.write(ENCODER.encode(emptyHeader));
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadCipherNoneFooterNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putBlock(formattedBuffer, OpenSshKeyIndicator.CIPHER_NAME_NONE.getIndicator());

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadCipherInvalid() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putBlock(formattedBuffer, INVALID_CIPHER.getBytes(StandardCharsets.UTF_8));

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        final UnrecoverableKeyException exception = assertThrows(UnrecoverableKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(INVALID_CIPHER));
    }

    @Test
    void testReadInvalidKeyCount() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putCipherKdfKeyCount(formattedBuffer, INVALID_KEY_COUNT);

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        final UnrecoverableKeyException exception = assertThrows(UnrecoverableKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(Integer.toString(INVALID_KEY_COUNT)));
    }

    @Test
    void testReadPublicKeyTypeNotValid() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putCipherKdfKeyCount(formattedBuffer, VALID_KEY_COUNT);

        final ByteBuffer publicKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putBlock(publicKeyBuffer, INVALID_KEY_TYPE.getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, publicKeyBuffer);

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        final UnrecoverableKeyException exception = assertThrows(UnrecoverableKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(INVALID_KEY_TYPE));
    }

    @Test
    void testReadPrivateKeyCheckNumbersNotMatched() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putCipherKdfKeyCount(formattedBuffer, VALID_KEY_COUNT);

        final ByteBuffer publicKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putBlock(publicKeyBuffer, SshKeyType.RSA.getKeyType().getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, publicKeyBuffer);

        final ByteBuffer privateKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        privateKeyBuffer.putInt(0);
        putBuffer(formattedBuffer, privateKeyBuffer);

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadPrivateKeyTypeInvalid() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putCipherKdfKeyCount(formattedBuffer, VALID_KEY_COUNT);

        final ByteBuffer publicKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putBlock(publicKeyBuffer, SshKeyType.RSA.getKeyType().getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, publicKeyBuffer);

        final ByteBuffer privateKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        putBlock(privateKeyBuffer, INVALID_KEY_TYPE.getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, privateKeyBuffer);

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        final UnrecoverableKeyException exception = assertThrows(UnrecoverableKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(INVALID_KEY_TYPE));
    }

    @Test
    void testReadPrivateKeyTypeNotMatched() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putCipherKdfKeyCount(formattedBuffer, VALID_KEY_COUNT);

        final ByteBuffer publicKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        final SshKeyType publicKeyType = SshKeyType.RSA;
        putBlock(publicKeyBuffer, publicKeyType.getKeyType().getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, publicKeyBuffer);

        final ByteBuffer privateKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        putBlock(privateKeyBuffer, SshKeyType.ED25519.getKeyType().getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, privateKeyBuffer);

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(publicKeyType.getKeyType()));
    }

    @Test
    void testReadPrivateKeyTypeUnsupported() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putCipherKdfKeyCount(formattedBuffer, VALID_KEY_COUNT);

        final SshKeyType sshKeyType = SshKeyType.ED25519;

        final ByteBuffer publicKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putBlock(publicKeyBuffer, sshKeyType.getKeyType().getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, publicKeyBuffer);

        final ByteBuffer privateKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        putBlock(privateKeyBuffer, sshKeyType.getKeyType().getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, privateKeyBuffer);

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        final ByteBuffer inputBuffer = ByteBuffer.wrap(outputStream.toByteArray());

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(sshKeyType.getKeyType()));
    }

    @Test
    void testReadBadPadding() throws IOException, GeneralSecurityException {
        final ByteBuffer rsaPrivateKeyBuffer = getRsaPrivateKeyBuffer();
        rsaPrivateKeyBuffer.put(INVALID_PADDING);

        final ByteBuffer rsaKeyPairBuffer = getRsaKeyPairBuffer(rsaPrivateKeyBuffer);

        assertThrows(BadPaddingException.class, () -> reader.read(rsaKeyPairBuffer));
    }

    @Test
    void testRead() throws IOException, GeneralSecurityException {
        final ByteBuffer rsaPrivateKeyBuffer = getRsaPrivateKeyBuffer();
        final ByteBuffer rsaKeyPairBuffer = getRsaKeyPairBuffer(rsaPrivateKeyBuffer);

        final KeyPair keyPair = reader.read(rsaKeyPairBuffer);

        assertKeyPairFound(keyPair);
    }

    static ByteBuffer getRsaKeyPairBuffer(final ByteBuffer privateKeyBuffer) throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(OpenSshKeyIndicator.HEADER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(ENCODER.encode(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator()));

        final ByteBuffer formattedBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putCipherKdfKeyCount(formattedBuffer, VALID_KEY_COUNT);

        final SshKeyType sshKeyType = SshKeyType.RSA;

        final ByteBuffer publicKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        putBlock(publicKeyBuffer, sshKeyType.getKeyType().getBytes(StandardCharsets.UTF_8));
        putBuffer(formattedBuffer, publicKeyBuffer);
        putBuffer(formattedBuffer, privateKeyBuffer);

        outputStream.write(getEncoded(formattedBuffer));
        writeFooter(outputStream);
        return ByteBuffer.wrap(outputStream.toByteArray());
    }

    static ByteBuffer getRsaPrivateKeyBuffer() throws NoSuchAlgorithmException {
        final ByteBuffer privateKeyBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        privateKeyBuffer.putInt(CHECK_NUMBER);
        putBlock(privateKeyBuffer, SshKeyType.RSA.getKeyType().getBytes(StandardCharsets.UTF_8));

        final SshRsaOpenSshKeyPairReaderTest sshRsaOpenSshKeyPairReaderTest = new SshRsaOpenSshKeyPairReaderTest();
        final ByteBuffer rsaPrivateKeyBuffer = sshRsaOpenSshKeyPairReaderTest.getPrivateKeyBuffer();
        privateKeyBuffer.put(rsaPrivateKeyBuffer);
        putBlock(privateKeyBuffer, EMPTY_BLOCK);
        privateKeyBuffer.put(VALID_PADDING);

        return privateKeyBuffer;
    }

    private static void assertKeyPairFound(final KeyPair keyPair) {
        assertNotNull(keyPair);

        final PrivateKey privateKey = keyPair.getPrivate();
        assertNotNull(privateKey);

        final PublicKey publicKey = keyPair.getPublic();
        assertNotNull(publicKey);

        assertEquals(RSA_ALGORITHM, privateKey.getAlgorithm());
        assertEquals(RSA_ALGORITHM, publicKey.getAlgorithm());
    }

    private static byte[] getEncoded(final ByteBuffer formattedBuffer) {
        formattedBuffer.flip();
        final byte[] bytes = new byte[formattedBuffer.remaining()];
        formattedBuffer.get(bytes);
        return ENCODER.encode(bytes);
    }

    private static void putBlock(final ByteBuffer buffer, final byte[] block) {
        buffer.putInt(block.length);
        buffer.put(block);
    }

    private static void putBuffer(final ByteBuffer buffer, final ByteBuffer inputBuffer) {
        inputBuffer.flip();
        final byte[] block = new byte[inputBuffer.remaining()];
        inputBuffer.get(block);
        putBlock(buffer, block);
    }

    private static void putCipherKdfKeyCount(final ByteBuffer buffer, final int keyCount) {
        putBlock(buffer, OpenSshKeyIndicator.CIPHER_NAME_NONE.getIndicator());
        putBlock(buffer, KDF_TYPE_NONE.getBytes(StandardCharsets.UTF_8));
        putBlock(buffer, EMPTY_BLOCK);
        buffer.putInt(keyCount);
    }

    private static void writeFooter(final OutputStream outputStream) throws IOException {
        outputStream.write(KeySeparator.LINE_FEED.getCode());
        outputStream.write(OpenSshKeyIndicator.FOOTER.getIndicator());
        outputStream.write(KeySeparator.LINE_FEED.getCode());
    }
}
