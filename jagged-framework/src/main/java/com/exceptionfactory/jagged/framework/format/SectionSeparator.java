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

/**
 * age-encryption Section Separator for File Header elements
 */
enum SectionSeparator {
    /** Line Feed Character */
    LINE_FEED(10),

    /** Space Character */
    SPACE(32);

    private final int code;

    SectionSeparator(final int code) {
        this.code = code;
    }

    int getCode() {
        return code;
    }
}
