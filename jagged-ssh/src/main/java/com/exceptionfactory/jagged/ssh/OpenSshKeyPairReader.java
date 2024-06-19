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

import javax.crypto.BadPaddingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * OpenSSH Key Version 1 implementation of Key Pair Reader described in openssh-portable/PROTOCOL.key
 */
class OpenSshKeyPairReader extends OpenSshKeyByteBufferReader {

    private static final int KEY_COUNT_SUPPORTED = 1;

    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private static final SshRsaOpenSshKeyPairReader SSH_RSA_OPEN_SSH_KEY_PAIR_READER = new SshRsaOpenSshKeyPairReader();

    /**
     * Read Public and Private Key Pair from buffer containing OpenSSH Key Version 1
     *
     * @param inputBuffer Input Buffer to be read
     * @return Public and Private Key Pair
     * @throws GeneralSecurityException Thrown on failures to parse input buffer
     */
    @Override
    public KeyPair read(final ByteBuffer inputBuffer) throws GeneralSecurityException {
        Objects.requireNonNull(inputBuffer, "Input Buffer required");

        readHeader(inputBuffer);

        final ByteBuffer decodedBuffer = getDecodedBuffer(inputBuffer);
        readMagicHeader(decodedBuffer);

        final byte[] cipherName = readBlock(decodedBuffer);
        if (Arrays.equals(OpenSshKeyIndicator.CIPHER_NAME_NONE.getIndicator(), cipherName)) {
            // Key Derivation Function Name not applicable for unencrypted processing
            readBlock(decodedBuffer);
            // Key Derivation Function Options not applicable for unencrypted processing
            readBlock(decodedBuffer);

            readKeyCount(decodedBuffer);

            final byte[] publicKeyEncoded = readBlock(decodedBuffer);
            final ByteBuffer publicKeyBuffer = ByteBuffer.wrap(publicKeyEncoded);
            final SshKeyType sshKeyType = readKeyType(publicKeyBuffer);

            final byte[] privateKeyEncoded = readBlock(decodedBuffer);
            final ByteBuffer privateKeyBuffer = ByteBuffer.wrap(privateKeyEncoded);

            return readKeyPair(sshKeyType, privateKeyBuffer);
        } else {
            final String cipherNameLabel = new String(cipherName, StandardCharsets.US_ASCII);
            throw new UnrecoverableKeyException(String.format("OpenSSH Key Cipher Name [%s] not supported", cipherNameLabel));
        }
    }

    private void readHeader(final ByteBuffer inputBuffer) throws InvalidKeyException {
        if (inputBuffer.remaining() > OpenSshKeyIndicator.HEADER.getLength()) {
            final byte[] header = new byte[OpenSshKeyIndicator.HEADER.getLength()];
            inputBuffer.get(header);
            if (Arrays.equals(OpenSshKeyIndicator.HEADER.getIndicator(), header)) {
                final byte character = inputBuffer.get();
                if (KeySeparator.CARRIAGE_RETURN.getCode() == character) {
                    final byte endCharacter = inputBuffer.get();
                    if (KeySeparator.LINE_FEED.getCode() != endCharacter) {
                        final String message = String.format("OpenSSH Key header line feed [%d] not found after carriage return", KeySeparator.LINE_FEED.getCode());
                        throw new InvalidKeyException(message);
                    }
                } else if (KeySeparator.LINE_FEED.getCode() != character) {
                    final String message = String.format("OpenSSH Key header end line feed [%d] not found", KeySeparator.LINE_FEED.getCode());
                    throw new InvalidKeyException(message);
                }
            } else {
                throw new InvalidKeyException("OpenSSH Key header not matched");
            }
        } else {
            throw new InvalidKeyException("OpenSSH Key header not found");
        }
    }

    protected SshKeyType readKeyType(final ByteBuffer buffer) throws GeneralSecurityException {
        final String keyType = readString(buffer);
        return Arrays.stream(SshKeyType.values())
                .filter(sshKeyType -> sshKeyType.getKeyType().equals(keyType))
                .findFirst()
                .orElseThrow(() -> new UnrecoverableKeyException(String.format("OpenSSH Key Type [%s] not supported", keyType)));
    }

    private KeyPair readKeyPair(final SshKeyType sshKeyType, final ByteBuffer privateKeyBuffer) throws GeneralSecurityException {
        final int firstCheckNumber = readInteger(privateKeyBuffer);
        final int secondCheckNumber = readInteger(privateKeyBuffer);

        if (firstCheckNumber == secondCheckNumber) {
            final KeyPair keyPair;

            final SshKeyType privateSshKeyType = readKeyType(privateKeyBuffer);
            if (sshKeyType == privateSshKeyType) {
                if (SshKeyType.RSA == privateSshKeyType) {
                    keyPair = SSH_RSA_OPEN_SSH_KEY_PAIR_READER.read(privateKeyBuffer);
                } else {
                    throw new InvalidKeyException(String.format("OpenSSH Private Key Type [%s] not supported", sshKeyType.getKeyType()));
                }
            } else {
                final String message = String.format("OpenSSH Private Key Type [%s] not matched [%s]", sshKeyType.getKeyType(), privateSshKeyType.getKeyType());
                throw new InvalidKeyException(message);
            }

            // Read comments
            readBlock(privateKeyBuffer);
            readPrivateKeyPadding(privateKeyBuffer);

            return keyPair;
        } else {
            throw new InvalidKeyException("OpenSSH Key check numbers not matched");
        }
    }

    private void readMagicHeader(final ByteBuffer decodedBuffer) throws InvalidKeyException {
        if (decodedBuffer.remaining() > OpenSshKeyIndicator.MAGIC_HEADER.getLength()) {
            final byte[] magicHeader = new byte[OpenSshKeyIndicator.MAGIC_HEADER.getLength()];
            decodedBuffer.get(magicHeader);
            if (!Arrays.equals(OpenSshKeyIndicator.MAGIC_HEADER.getIndicator(), magicHeader)) {
                throw new InvalidKeyException("OpenSSH Key AUTH_MAGIC header not matched");
            }
        } else {
            throw new InvalidKeyException("OpenSSH Key AUTH_MAGIC header not found");
        }
    }

    private void readKeyCount(final ByteBuffer decodedBuffer) throws GeneralSecurityException {
        final int keyCount = readInteger(decodedBuffer);
        if (KEY_COUNT_SUPPORTED != keyCount) {
            throw new UnrecoverableKeyException(String.format("OpenSSH Key Count [%d] not supported", keyCount));
        }
    }

    private void readPrivateKeyPadding(final ByteBuffer buffer) throws BadPaddingException {
        int padExpected = 1;
        while (buffer.hasRemaining()) {
            final byte pad = buffer.get();
            if (padExpected != pad) {
                throw new BadPaddingException(String.format("Private Key Padding Character [%d] does not match expected [%d]", pad, padExpected));
            }
        }
    }

    private ByteBuffer getDecodedBuffer(final ByteBuffer inputBuffer) throws InvalidKeyException {
        final ByteBuffer encodedBuffer = ByteBuffer.allocate(inputBuffer.limit());

        while (inputBuffer.hasRemaining()) {
            final byte[] lineEncoded = readLineEncoded(inputBuffer);
            if (Arrays.equals(OpenSshKeyIndicator.FOOTER.getIndicator(), lineEncoded)) {
                break;
            }

            encodedBuffer.put(lineEncoded);
        }

        encodedBuffer.flip();
        try {
            return DECODER.decode(encodedBuffer);
        } catch (final IllegalArgumentException e) {
            throw new InvalidKeyException("OpenSSH Key Base64 decoding failed", e);
        }
    }

    private byte[] readLineEncoded(final ByteBuffer inputBuffer) {
        final int startPosition = inputBuffer.position();
        int endPosition = startPosition;
        int nextStartPosition = startPosition;

        while (inputBuffer.hasRemaining()) {
            final byte character = inputBuffer.get();
            if (KeySeparator.CARRIAGE_RETURN.getCode() == character) {
                final byte endCharacter = inputBuffer.get();

                final int lastPosition = inputBuffer.position();
                if (KeySeparator.LINE_FEED.getCode() != endCharacter) {
                    inputBuffer.position(lastPosition);
                }

                nextStartPosition = inputBuffer.position();
                break;
            } else if (KeySeparator.LINE_FEED.getCode() == character) {
                nextStartPosition = inputBuffer.position();
                break;
            }

            endPosition = inputBuffer.position();
        }

        final int length = endPosition - startPosition;
        final byte[] lineEncoded = new byte[length];
        inputBuffer.position(startPosition);
        inputBuffer.get(lineEncoded);

        if (nextStartPosition == startPosition) {
            inputBuffer.position(endPosition);
        } else {
            inputBuffer.position(nextStartPosition);
        }

        return lineEncoded;
    }
}
