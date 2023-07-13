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

/**
 * Abstraction for producing Header MAC Key using HMAC-based Extract-and-Expand Key Derivation Function described in RFC 5869
 */
public interface HeaderKeyProducer {
    /**
     * Get derived Header Message Authentication Code Key
     *
     * @param fileKey File Key
     * @return Message Authentication Code Header Key
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    MacKey getHeaderKey(FileKey fileKey) throws GeneralSecurityException;
}
