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
package com.exceptionfactory.jagged;

import java.io.IOException;

/**
 * Payload Exception indicating problems reading or writing File Payload
 */
public class PayloadException extends IOException {
    /**
     * Payload Exception with message
     *
     * @param message Message describing the problem with the Payload
     */
    public PayloadException(final String message) {
        super(message);
    }

    /**
     * Payload Exception with message and cause
     *
     * @param message Message describing the problem with the Payload
     * @param cause Throwable cause for the Payload Exception
     */
    public PayloadException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
