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
package com.exceptionfactory.jagged.ssh;

/**
 * Separator for encoded key elements
 */
enum KeySeparator {
    /** Line Feed Character */
    LINE_FEED(10),

    /** Carriage Return Character */
    CARRIAGE_RETURN(13);

    private final byte code;

    KeySeparator(final int code) {
        this.code = (byte) code;
    }

    byte getCode() {
        return code;
    }
}
