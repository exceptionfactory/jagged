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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Abstraction for reading age file header containing one or more Recipient Stanzas
 */
interface FileHeaderReader {
    /**
     * Get File Header with Recipient Stanzas from Channel that starts with standard age header
     *
     * @param inputBuffer Input Byte Buffer starting with age header
     * @return File Header with Recipient Stanzas containing one or more elements
     * @throws GeneralSecurityException Thrown on failure to read or process File Header bytes
     */
    FileHeader getFileHeader(ByteBuffer inputBuffer) throws GeneralSecurityException;
}
