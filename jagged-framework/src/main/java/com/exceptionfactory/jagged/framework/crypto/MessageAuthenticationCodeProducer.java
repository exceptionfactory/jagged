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

import java.nio.ByteBuffer;

/**
 * Producer abstraction for generating a Keyed-Hash Message Authentication Code as described in RFC 2104
 */
public interface MessageAuthenticationCodeProducer {
    /**
     * Get Message Authentication Code using configured Key and provided input bytes
     *
     * @param inputBuffer Input Buffer from which to produce a Message Authentication Code
     * @return Message Authentication Code bytes
     */
    byte[] getMessageAuthenticationCode(ByteBuffer inputBuffer);
}
