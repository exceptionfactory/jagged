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

/**
 * Byte Buffer Cipher Operation Factory provides instances of Byte Buffer Decryptor and Encryptor objects
 */
public final class ByteBufferCipherOperationFactory {
    private ByteBufferCipherOperationFactory() {

    }

    /**
     * Create new instance of Byte Buffer Decryptor using provided Key and Initialization Vector
     *
     * @param cipherKey Cipher Key required
     * @param parameterSpec Initialization Vector parameter specification required
     * @return Byte Buffer Decryptor
     * @throws GeneralSecurityException Thrown on decryptor initialization failures
     */
    public static ByteBufferDecryptor newByteBufferDecryptor(final CipherKey cipherKey, final IvParameterSpec parameterSpec) throws GeneralSecurityException {
        return new StandardByteBufferDecryptor(cipherKey, parameterSpec);
    }

    /**
     * Create new instance of Byte Buffer Encryptor using provided Key and Initialization Vector
     *
     * @param cipherKey Cipher Key required
     * @param parameterSpec Initialization Vector parameter specification required
     * @return Byte Buffer Encryptor
     * @throws GeneralSecurityException Thrown on encryptor initialization failures
     */
    public static ByteBufferEncryptor newByteBufferEncryptor(final CipherKey cipherKey, final IvParameterSpec parameterSpec) throws GeneralSecurityException {
        return new StandardByteBufferEncryptor(cipherKey, parameterSpec);
    }
}
