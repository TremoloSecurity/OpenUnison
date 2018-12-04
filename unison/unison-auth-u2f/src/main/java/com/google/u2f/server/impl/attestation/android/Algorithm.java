/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
 *******************************************************************************/
package com.google.u2f.server.impl.attestation.android;

import java.security.cert.CertificateParsingException;

/**
 * Keysmaster algorithm values as taken from: keymaster_defs.h / KeymasterDefs.java
 */
public enum Algorithm {
  /* Asymmetric algorithms. */
  KM_ALGORITHM_RSA(1, "rsa"),
  KM_ALGORITHM_EC(3, "ec"),

  /* Block ciphers algorithms */
  KM_ALGORITHM_AES(32, "aes"),

  /* MAC algorithms */
  KM_ALGORITHM_HMAC(128, "hmac");

  private final int value;
  private final String description;

  public static Algorithm fromValue(int value) throws CertificateParsingException {
    for (Algorithm algorithm : Algorithm.values()) {
      if (algorithm.getValue() == value) {
        return algorithm;
      }
    }

    throw new CertificateParsingException("Invalid algorithm value: " + value);
  }

  private Algorithm(int value, String description) {
    this.value = value;
    this.description = description;
  }

  public int getValue() {
    return value;
  }

  @Override
  public String toString() {
    return description;
  }
}
