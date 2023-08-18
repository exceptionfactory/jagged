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

import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Objects;

/**
 * Standard implementation of Byte Buffer Cipher Factory provides instances of Byte Buffer Decryptor and Encryptor objects
 */
public final class StandardByteBufferCipherFactory implements ByteBufferCipherFactory {
    private final CipherFactory cipherFactory;

    /**
     * Standard Byte Buffer Cipher Factory constructor using default Security Provider configuration
     */
    public StandardByteBufferCipherFactory() {
        cipherFactory = new CipherFactory();
    }

    /**
     * Standard Byte Buffer Cipher Factory constructor using specified Security Provider configuration
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    public StandardByteBufferCipherFactory(final Provider provider) {
        Objects.requireNonNull(provider, "Provider required");
        cipherFactory = new CipherFactory(provider);
    }

    /**
     * Create new instance of Byte Buffer Decryptor using provided Key and Initialization Vector
     *
     * @param cipherKey Cipher Key required
     * @param parameterSpec Initialization Vector parameter specification required
     * @return Byte Buffer Decryptor
     * @throws GeneralSecurityException Thrown on decryptor initialization failures
     */
    @Override
    public ByteBufferDecryptor newByteBufferDecryptor(final CipherKey cipherKey, final IvParameterSpec parameterSpec) throws GeneralSecurityException {
        return new StandardByteBufferDecryptor(cipherFactory, cipherKey, parameterSpec);
    }

    /**
     * Create new instance of Byte Buffer Encryptor using provided Key and Initialization Vector
     *
     * @param cipherKey Cipher Key required
     * @param parameterSpec Initialization Vector parameter specification required
     * @return Byte Buffer Encryptor
     * @throws GeneralSecurityException Thrown on encryptor initialization failures
     */
    @Override
    public ByteBufferEncryptor newByteBufferEncryptor(final CipherKey cipherKey, final IvParameterSpec parameterSpec) throws GeneralSecurityException {
        return new StandardByteBufferEncryptor(cipherFactory, cipherKey, parameterSpec);
    }
}
