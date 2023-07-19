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
package com.exceptionfactory.jagged.framework.format;

import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Standard implementation of File Header Reader
 */
final class StandardFileHeaderReader implements FileHeaderReader {
    /** Maximum Line Length indicated wrapping lines as described in age-encryption Recipient Stanza section */
    private static final int MAXIMUM_LINE_LENGTH = 64;

    /** Encoded Message Authentication Code Length in bytes of Base64 characters */
    private static final int ENCODED_MAC_LENGTH = 43;

    /** Minimum valid printable ASCII Character Code */
    private static final byte EXCLAMATION_MARK_CHARACTER = 33;

    /** Maximum valid printable ASCII Character Code */
    private static final byte TILDE_CHARACTER_CODE = 126;

    private static final CanonicalBase64.Decoder DECODER = CanonicalBase64.getDecoder();

    /**
     * Get File Header containing Recipient Stanzas from buffer that starts with standard age header
     *
     * @param inputBuffer Input Byte Buffer starting with age header
     * @return File Header with Recipient Stanzas
     * @throws GeneralSecurityException Thrown on failure to read or process File Header bytes
     */
    @Override
    public FileHeader getFileHeader(final ByteBuffer inputBuffer) throws GeneralSecurityException {
        Objects.requireNonNull(inputBuffer, "Input Buffer required");
        readVersion(inputBuffer);
        final List<RecipientStanza> recipientStanzas = readRecipientStanzas(inputBuffer);

        if (inputBuffer.hasRemaining()) {
            final byte separator = inputBuffer.get();
            if (SectionSeparator.SPACE.getCode() == separator) {
                final byte[] messageAuthenticationCode = readMessageAuthenticationCode(inputBuffer);
                return new StandardFileHeader(recipientStanzas, messageAuthenticationCode);
            } else {
                final String message = String.format("Byte [%d] found instead of Space after End Header", separator);
                throw new HeaderDecodingException(message);
            }
        } else {
            throw new HeaderDecodingException("Message Authentication Code not found after Recipient Stanzas");
        }
    }

    /**
     * Read version with trailing line feed
     *
     * @param inputBuffer Header buffer
     * @throws HeaderDecodingException Thrown on failure to find version or line feed
     */
    private void readVersion(final ByteBuffer inputBuffer) throws HeaderDecodingException {
        if (SectionIndicator.VERSION.getLength() >= inputBuffer.remaining()) {
            throw new HeaderDecodingException("Version not found");
        }

        final byte[] version = new byte[SectionIndicator.VERSION.getLength()];
        inputBuffer.get(version);

        if (Arrays.equals(SectionIndicator.VERSION.getIndicator(), version)) {
            final byte code = inputBuffer.get();
            if (SectionSeparator.LINE_FEED.getCode() != code) {
                throw new HeaderDecodingException(String.format("Byte [%d] found instead of Line Feed after Version", code));
            }
        } else {
            throw new HeaderDecodingException("Supported version not found");
        }
    }

    private List<RecipientStanza> readRecipientStanzas(final ByteBuffer inputBuffer) throws HeaderDecodingException {
        final List<RecipientStanza> recipientStanzas = new ArrayList<>();

        while (inputBuffer.hasRemaining()) {
            final int inputPosition = inputBuffer.position();

            final byte[] argumentIndicator = new byte[SectionIndicator.STANZA.getLength()];
            inputBuffer.get(argumentIndicator);
            if (Arrays.equals(SectionIndicator.STANZA.getIndicator(), argumentIndicator)) {
                final String type = readType(inputBuffer);
                final List<String> arguments = readArguments(inputBuffer);
                final byte[] body = readBody(inputBuffer);
                final RecipientStanza recipientStanza = new StandardRecipientStanza(type, arguments, body);
                recipientStanzas.add(recipientStanza);
            } else if (Arrays.equals(SectionIndicator.END.getIndicator(), argumentIndicator)) {
                // End of header indicates Recipient Stanzas read completed
                break;
            } else {
                // Reset Buffer position on unrecognized section indicator
                inputBuffer.position(inputPosition);
                break;
            }
        }

        return recipientStanzas;
    }

    private String readType(final ByteBuffer inputBuffer) {
        final StringBuilder builder = new StringBuilder();

        while (inputBuffer.hasRemaining()) {
            final int inputPosition = inputBuffer.position();

            final byte read = inputBuffer.get();
            if (SectionSeparator.SPACE.getCode() == read || SectionSeparator.LINE_FEED.getCode() == read) {
                inputBuffer.position(inputPosition);
                break;
            } else {
                final char character = (char) read;
                builder.append(character);
            }
        }

        return builder.toString();
    }

    private List<String> readArguments(final ByteBuffer inputBuffer) throws HeaderDecodingException {
        final List<String> arguments = new ArrayList<>();
        StringBuilder builder = new StringBuilder();

        byte lastRead = 0;
        while (inputBuffer.hasRemaining()) {
            final byte read = inputBuffer.get();
            if (SectionSeparator.LINE_FEED.getCode() == read) {
                setArgument(builder, arguments);
                break;
            } else if (SectionSeparator.SPACE.getCode() == read) {
                if (SectionSeparator.SPACE.getCode() == lastRead) {
                    throw new HeaderDecodingException("Recipient Stanza empty argument found");
                }
                setArgument(builder, arguments);
                builder = new StringBuilder();
            } else {
                if (isInvalidCharacter(read)) {
                    final String message = String.format("Recipient Stanza invalid character code [%d]", read);
                    throw new HeaderDecodingException(message);
                }
                final char character = (char) read;
                builder.append(character);
            }
            lastRead = read;
        }

        return arguments;
    }

    private void setArgument(final StringBuilder builder, final List<String> arguments) {
        if (builder.length() > 0) {
            final String argument = builder.toString();
            arguments.add(argument);
        }
    }

    /**
     * Read Recipient Stanza Body consisting of zero or more lines of Base64 characters with the last line shorter than 64 characters
     *
     * @param inputBuffer Header buffer
     * @return Recipient Stanza Body decoded
     * @throws HeaderDecodingException Thrown on failures to decode Base64 characters
     */
    private byte[] readBody(final ByteBuffer inputBuffer) throws HeaderDecodingException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int lineLength = 0;
        while (inputBuffer.hasRemaining()) {
            final byte read = inputBuffer.get();
            if (SectionSeparator.LINE_FEED.getCode() == read) {
                if (lineLength < MAXIMUM_LINE_LENGTH) {
                    break;
                } else if (lineLength > MAXIMUM_LINE_LENGTH) {
                    final String message = String.format("Recipient Stanza Body line length [%d] greater than maximum [%d]", lineLength, MAXIMUM_LINE_LENGTH);
                    throw new HeaderDecodingException(message);
                }
                lineLength = 0;
            } else {
                lineLength++;
                outputStream.write(read);
            }
        }
        final byte[] encoded = outputStream.toByteArray();
        try {
            return DECODER.decode(encoded);
        } catch (final RuntimeException e) {
            throw new HeaderDecodingException("Recipient Stanza Body decoding failed", e);
        }
    }

    /**
     * Read Message Authentication Code consisting of 43 Base64 characters with a Line Feed following
     *
     * @param buffer Header buffer
     * @return Decoded Message Authentication Code of 32 bytes
     * @throws HeaderDecodingException Thrown on end of buffer or missing line feed
     */
    private byte[] readMessageAuthenticationCode(final ByteBuffer buffer) throws HeaderDecodingException {
        if (buffer.remaining() < ENCODED_MAC_LENGTH) {
            throw new HeaderDecodingException("Message Authentication Code not found");
        }

        final byte[] encoded = new byte[ENCODED_MAC_LENGTH];
        buffer.get(encoded);
        final byte[] decoded = getDecoded(encoded);
        final byte code = buffer.get();
        if (SectionSeparator.LINE_FEED.getCode() == code) {
            return decoded;
        } else {
            final String message = String.format("Byte [%d] found instead of Line Feed after Message Authentication Code", code);
            throw new HeaderDecodingException(message);
        }
    }

    private boolean isInvalidCharacter(final byte character) {
        return character < EXCLAMATION_MARK_CHARACTER || character > TILDE_CHARACTER_CODE;
    }

    private byte[] getDecoded(final byte[] encoded) throws HeaderDecodingException {
        try {
            return DECODER.decode(encoded);
        } catch (final IllegalArgumentException e) {
            throw new HeaderDecodingException("Message Authentication Code decoding failed", e);
        }
    }
}
