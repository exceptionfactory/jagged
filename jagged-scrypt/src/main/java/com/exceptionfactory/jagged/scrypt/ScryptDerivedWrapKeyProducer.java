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

import com.exceptionfactory.jagged.framework.crypto.CipherKey;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

import static com.exceptionfactory.jagged.scrypt.RecipientIndicator.SALT_LABEL;

/**
 * Standard implementation of Wrap Key Producer using scrypt with block size of 8 and parallelization of 1
 */
class ScryptDerivedWrapKeyProducer implements DerivedWrapKeyProducer {

    private static final int LABELED_SALT_LENGTH = 44;

    private static final byte[] SALT_LABEL_BYTES = SALT_LABEL.getIndicator().getBytes(StandardCharsets.UTF_8);

    private final byte[] passphrase;

    /**
     * Standard Wrap Key Producer with required passphrase for scrypt key derivation
     *
     * @param passphrase Passphrase required
     */
    ScryptDerivedWrapKeyProducer(final byte[] passphrase) {
        this.passphrase = Objects.requireNonNull(passphrase, "Passphrase required");
    }

    /**
     * Get Wrap Key
     *
     * @param salt Salt array of 16 bytes to derive scrypt S parameter
     * @param workFactor Work factor to derive scrypt N parameter
     * @return Recipient Stanza Cipher Key for decrypting File Key
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    @Override
    public CipherKey getWrapKey(final byte[] salt, final int workFactor) throws GeneralSecurityException {
        final byte[] labeledSalt = getLabeledSalt(salt);
        final byte[] wrapKey = ScryptFunction.getDerivedKey(passphrase, labeledSalt, workFactor);
        return new CipherKey(wrapKey);
    }

    private byte[] getLabeledSalt(final byte[] saltArgument) {
        final byte[] labeledSalt = new byte[LABELED_SALT_LENGTH];
        System.arraycopy(SALT_LABEL_BYTES, 0, labeledSalt, 0, SALT_LABEL_BYTES.length);
        System.arraycopy(saltArgument, 0, labeledSalt, SALT_LABEL_BYTES.length, saltArgument.length);
        return labeledSalt;
    }
}
