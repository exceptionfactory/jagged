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
package com.exceptionfactory.jagged.framework.armor;

import java.io.IOException;

/**
 * Armored Decoding Exception indicates failures while reading age encryption armored messages
 */
public class ArmoredDecodingException extends IOException {
    /**
     * Armored Decoding Exception with required message indicating problem details
     *
     * @param message Exception message with problem details
     */
    public ArmoredDecodingException(final String message) {
        super(message);
    }

    /**
     * Armored Decoding Exception with required message indicating problem details
     *
     * @param message Exception message with problem details
     * @param cause Throwable cause of armored decoding failures
     */
    public ArmoredDecodingException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
