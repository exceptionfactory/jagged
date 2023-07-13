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

import com.exceptionfactory.jagged.FileKey;

import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Standard implementation with HKDF-SHA-256 for Header Message Authentication Code Key verification
 */
class StandardHeaderKeyProducer extends HashedDerivedKeyProducer implements HeaderKeyProducer {
    /** Empty Salt as described in age-encryption Header MAC key derivation */
    private static final byte[] EMPTY_SALT = new byte[CryptographicKeyType.HEADER_KEY.getKeyLength()];

    /** Empty Salt Key with expected Key Type */
    private static final MacKey EMPTY_SALT_KEY = new MacKey(EMPTY_SALT, CryptographicKeyType.HEADER_KEY);

    /** Header Application Information for HKDF-SHA-256 as described in age-encryption Header MAC key derivation */
    private static final byte[] HEADER_INFO = new byte[]{'h', 'e', 'a', 'd', 'e', 'r'};

    /**
     * Get derived Header Message Authentication Code Key as described in age-encryption Header MAC key derivation
     *
     * @param fileKey File Key
     * @return Message Authentication Code Header Key
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    @Override
    public MacKey getHeaderKey(final FileKey fileKey) throws GeneralSecurityException {
        Objects.requireNonNull(fileKey, "File Key required");
        final byte[] headerKey = getDerivedKey(fileKey, EMPTY_SALT_KEY, HEADER_INFO);
        return new MacKey(headerKey, CryptographicKeyType.HEADER_KEY);
    }
}
