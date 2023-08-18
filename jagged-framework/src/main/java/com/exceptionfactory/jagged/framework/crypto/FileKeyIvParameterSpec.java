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

/**
 * Initialization Vector Parameter Specification for File Key encryption and decryption consisting of 12 zero bytes
 */
final class FileKeyIvParameterSpec extends IvParameterSpec {
    private static final int INITIALIZATION_VECTOR_LENGTH = 12;

    private static final byte[] STANDARD_INITIALIZATION_VECTOR = new byte[INITIALIZATION_VECTOR_LENGTH];

    /**
     * File Key Initialization Vector Parameter Specification with array of 12 bytes
     */
    FileKeyIvParameterSpec() {
        super(STANDARD_INITIALIZATION_VECTOR);
    }
}
