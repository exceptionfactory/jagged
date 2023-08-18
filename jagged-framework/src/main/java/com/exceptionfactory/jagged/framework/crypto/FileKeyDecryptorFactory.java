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

import java.security.Provider;
import java.util.Objects;

/**
 * Factory abstraction for instances of File Key Decryptor
 */
public final class FileKeyDecryptorFactory {
    private final Provider provider;

    /**
     * File Key Decryptor Factory uses the system default Security Provider configuration
     */
    public FileKeyDecryptorFactory() {
        provider = null;
    }

    /**
     * File Key Decryptor Factory with support for custom Security Provider
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    public FileKeyDecryptorFactory(final Provider provider) {
        this.provider = Objects.requireNonNull(provider, "Provider required");
    }

    /**
     * Create new instance of File Key Decryptor using current configuration
     *
     * @return File Key Decryptor
     */
    public FileKeyDecryptor newFileKeyDecryptor() {
        return provider == null ? new StandardFileKeyDecryptor() : new StandardFileKeyDecryptor(provider);
    }
}
