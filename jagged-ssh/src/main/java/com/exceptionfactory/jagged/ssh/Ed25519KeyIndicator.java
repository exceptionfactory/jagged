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
 * Ed25519 Key indicator fields
 */
enum Ed25519KeyIndicator {
    /** Algorithm */
    KEY_ALGORITHM("Ed25519"),

    /** Format */
    KEY_FORMAT("RAW");

    private final String indicator;

    Ed25519KeyIndicator(final String indicator) {
        this.indicator = indicator;
    }

    String getIndicator() {
        return indicator;
    }
}
