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

import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Abstraction for converting Ed25519 keys to X25519 keys
 */
interface Ed25519KeyConverter {
    /**
     * Get X25519 Private Key from Ed25519 Private Key using first 32 bytes of SHA-512 digested key
     *
     * @param ed25519PrivateKey Ed25519 private key
     * @return X25519 Private Key
     * @throws GeneralSecurityException Thrown on failure to convert private key
     */
    PrivateKey getPrivateKey(Ed25519PrivateKey ed25519PrivateKey) throws GeneralSecurityException;

    /**
     * Get X25519 Private Key from SSH Ed25519 derived key
     *
     * @param derivedKey SSH Ed25519 derived key
     * @return X25519 Private Key
     * @throws GeneralSecurityException Thrown on failure to convert private key
     */
    PrivateKey getPrivateKey(SshEd25519DerivedKey derivedKey) throws GeneralSecurityException;

    /**
     * Get X25519 Public Key from Ed25519 Public Key computed using birational mapping described in RFC 7748 Section 4.1
     *
     * @param ed25519PublicKey Ed25519 public key
     * @return X25519 Public Key
     * @throws GeneralSecurityException Thrown on failure to convert public key
     */
    PublicKey getPublicKey(Ed25519PublicKey ed25519PublicKey) throws GeneralSecurityException;

    /**
     * Get X25519 Public Key from computed Shared Secret Key
     *
     * @param sharedSecretKey Computed shared secret key
     * @return X25519 Public Key
     * @throws GeneralSecurityException Thrown on key processing failures
     */
    PublicKey getPublicKey(SharedSecretKey sharedSecretKey) throws GeneralSecurityException;
}
