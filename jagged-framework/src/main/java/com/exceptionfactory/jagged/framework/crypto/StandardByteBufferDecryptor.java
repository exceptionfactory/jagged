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
package com.exceptionfactory.jagged.framework.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Standard implementation of Byte Buffer Decryptor using javax.crypto.Cipher
 */
final class StandardByteBufferDecryptor implements ByteBufferDecryptor {
    private final Cipher cipher;

    /**
     * Standard Byte Buffer Decryptor constructor with required arguments
     *
     * @param cipherKey Cipher Key required
     * @param parameterSpec Initialization Vector parameter specification required
     * @throws GeneralSecurityException Thrown on Cipher initialization failures
     */
    StandardByteBufferDecryptor(final CipherKey cipherKey, final IvParameterSpec parameterSpec) throws GeneralSecurityException {
        Objects.requireNonNull(cipherKey, "Cipher Key required");
        Objects.requireNonNull(parameterSpec, "Parameter Specification required");
        this.cipher = CipherFactory.getInitializedCipher(CipherFactory.CipherMode.DECRYPT, cipherKey, parameterSpec);
    }

    /**
     * Read encrypted input buffer and write decrypted bytes to output buffer using javax.crypto.Cipher
     *
     * @param inputBuffer Encrypted Input Byte Buffer required
     * @param outputBuffer Decrypted Output Byte Buffer required
     * @return Number of bytes stored in Output Byte Buffer
     * @throws GeneralSecurityException Thrown on decryption failures
     */
    @Override
    public int decrypt(final ByteBuffer inputBuffer, final ByteBuffer outputBuffer) throws GeneralSecurityException {
        Objects.requireNonNull(inputBuffer, "Input Buffer required");
        Objects.requireNonNull(outputBuffer, "Output Buffer required");
        return cipher.doFinal(inputBuffer, outputBuffer);
    }
}
