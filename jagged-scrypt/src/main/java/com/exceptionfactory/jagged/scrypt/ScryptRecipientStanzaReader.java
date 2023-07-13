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
package com.exceptionfactory.jagged.scrypt;

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferCipherOperationFactory;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferDecryptor;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.FileKeyIvParameterSpec;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.exceptionfactory.jagged.scrypt.RecipientIndicator.STANZA_TYPE;

/**
 * Standard age-encryption Recipient Stanza Reader implementation using scrypt password encryption described in RFC 7914
 */
class ScryptRecipientStanzaReader implements RecipientStanzaReader {
    private static final int ENCRYPTED_FILE_KEY_LENGTH = 32;

    private static final int FILE_KEY_LENGTH = 16;

    private static final int ENCODED_SALT_LENGTH = 22;

    private static final int MAX_WORK_FACTOR = 20;

    private static final int MIN_WORK_FACTOR = 2;

    private static final Pattern WORK_FACTOR_PATTERN = Pattern.compile("^[1-9][0-9]?$");

    private static final CanonicalBase64.Decoder BASE64_DECODER = CanonicalBase64.getDecoder();

    private final DerivedWrapKeyProducer derivedWrapKeyProducer;

    ScryptRecipientStanzaReader(final DerivedWrapKeyProducer derivedWrapKeyProducer) {
        this.derivedWrapKeyProducer = Objects.requireNonNull(derivedWrapKeyProducer, "Wrap Key Producer required");
    }

    /**
     * Get File Key from matching scrypt Recipient Stanza
     *
     * @param recipientStanzas One or more Recipient Stanzas parsed from the age file header
     * @return File Key decrypted from matching scrypt Recipient Stanza arguments
     * @throws GeneralSecurityException Thrown on failure to read or decrypt File Key
     */
    @Override
    public FileKey getFileKey(final Iterable<RecipientStanza> recipientStanzas) throws GeneralSecurityException {
        Objects.requireNonNull(recipientStanzas, "Recipient Stanzas required");

        final List<Exception> exceptions = new ArrayList<>();

        final Iterator<RecipientStanza> stanzas = recipientStanzas.iterator();
        if (stanzas.hasNext()) {
            final RecipientStanza recipientStanza = stanzas.next();
            final String recipientStanzaType = recipientStanza.getType();
            if (STANZA_TYPE.getIndicator().equals(recipientStanzaType)) {
                if (stanzas.hasNext()) {
                    throw new UnsupportedRecipientStanzaException("Multiple Recipient Stanzas not allowed");
                }

                try {
                    return getFileKey(recipientStanza);
                } catch (final Exception e) {
                    exceptions.add(e);
                }
            } else {
                throw new UnsupportedRecipientStanzaException(String.format("%s Recipient Stanzas rejected", recipientStanzaType));
            }
        }

        if (exceptions.isEmpty()) {
            throw new UnsupportedRecipientStanzaException(String.format("%s Recipient Stanzas not found", STANZA_TYPE.getIndicator()));
        } else {
            final String message = String.format("%s Recipient Stanzas not matching", STANZA_TYPE.getIndicator());
            final UnsupportedRecipientStanzaException exception = new UnsupportedRecipientStanzaException(message);
            exceptions.forEach(exception::addSuppressed);
            throw exception;
        }
    }

    private FileKey getFileKey(final RecipientStanza recipientStanza) throws GeneralSecurityException {
        final Iterator<String> arguments = recipientStanza.getArguments().iterator();
        final byte[] saltArgument = getSaltArgument(arguments);
        final int workFactor = getWorkFactor(arguments);
        if (arguments.hasNext()) {
            final String message = String.format("%s Recipient Stanza extra argument not expected", STANZA_TYPE.getIndicator());
            throw new UnsupportedRecipientStanzaException(message);
        }
        final CipherKey wrapKey = derivedWrapKeyProducer.getWrapKey(saltArgument, workFactor);

        final byte[] encryptedFileKey = recipientStanza.getBody();
        final int encryptedFileKeyLength = encryptedFileKey.length;
        if (encryptedFileKeyLength == ENCRYPTED_FILE_KEY_LENGTH) {
            return getFileKey(encryptedFileKey, wrapKey);
        } else {
            final String message = String.format("Recipient Stanza Body length [%d] not required length [%d]", encryptedFileKeyLength, ENCRYPTED_FILE_KEY_LENGTH);
            throw new UnsupportedRecipientStanzaException(message);
        }
    }

    private FileKey getFileKey(final byte[] encryptedFileKey, final CipherKey wrapKey) throws GeneralSecurityException {
        final ByteBuffer encryptedFileKeyBuffer = ByteBuffer.wrap(encryptedFileKey);
        final FileKeyIvParameterSpec parameterSpec = new FileKeyIvParameterSpec();
        final ByteBufferDecryptor byteBufferDecryptor = ByteBufferCipherOperationFactory.newByteBufferDecryptor(wrapKey, parameterSpec);

        final ByteBuffer fileKeyBuffer = ByteBuffer.allocate(FILE_KEY_LENGTH);
        byteBufferDecryptor.decrypt(encryptedFileKeyBuffer, fileKeyBuffer);
        final byte[] fileKey = fileKeyBuffer.array();
        return new FileKey(fileKey);
    }

    private byte[] getSaltArgument(final Iterator<String> arguments) throws UnsupportedRecipientStanzaException {
        if (arguments.hasNext()) {
            final String saltArgumentEncoded = arguments.next();
            final int encodedLength = saltArgumentEncoded.length();
            if (encodedLength == ENCODED_SALT_LENGTH) {
                final byte[] saltArgumentEncodedBytes = saltArgumentEncoded.getBytes(StandardCharsets.US_ASCII);
                return BASE64_DECODER.decode(saltArgumentEncodedBytes);
            } else {
                final String message = String.format("Salt argument length [%d] not required length [%d]", encodedLength, ENCODED_SALT_LENGTH);
                throw new UnsupportedRecipientStanzaException(message);
            }
        } else {
            throw new UnsupportedRecipientStanzaException("Salt argument not found");
        }
    }

    private int getWorkFactor(final Iterator<String> arguments) throws UnsupportedRecipientStanzaException {
        if (arguments.hasNext()) {
            final String workFactorArgument = arguments.next();
            final Matcher workFactorMatcher = WORK_FACTOR_PATTERN.matcher(workFactorArgument);
            if (workFactorMatcher.matches()) {
                final int workFactor = Integer.parseInt(workFactorArgument);
                if (workFactor > MAX_WORK_FACTOR) {
                    throw new UnsupportedRecipientStanzaException(String.format("Work Factor [%d] greater than maximum [%d]", workFactor, MAX_WORK_FACTOR));
                } else if (workFactor < MIN_WORK_FACTOR) {
                    throw new UnsupportedRecipientStanzaException(String.format("Work Factor [%d] less than minimum [%d]", workFactor, MIN_WORK_FACTOR));
                }
                return workFactor;
            } else {
                throw new UnsupportedRecipientStanzaException(String.format("Work Factor argument [%s] not valid", workFactorArgument));
            }
        } else {
            throw new UnsupportedRecipientStanzaException("Work Factor argument not found");
        }
    }
}
