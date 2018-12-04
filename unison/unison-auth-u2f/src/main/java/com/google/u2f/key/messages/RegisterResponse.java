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
// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.google.u2f.key.messages;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

public class RegisterResponse extends U2FResponse {
  private final byte[] userPublicKey;
  private final byte[] keyHandle;
  private final X509Certificate attestationCertificate;
  private final byte[] signature;

  public RegisterResponse(byte[] userPublicKey, byte[] keyHandle,
      X509Certificate attestationCertificate, byte[] signature) {
    super();
    this.userPublicKey = userPublicKey;
    this.keyHandle = keyHandle;
    this.attestationCertificate = attestationCertificate;
    this.signature = signature;
  }

  /**
   * This is the (uncompressed) x,y-representation of a curve point on the P-256
   * NIST elliptic curve.
   */
  public byte[] getUserPublicKey() {
    return userPublicKey;
  }

  /**
   * This a handle that allows the U2F token to identify the generated key pair.
   * U2F tokens MAY wrap the generated private key and the application id it was
   * generated for, and output that as the key handle.
   */
  public byte[] getKeyHandle() {
    return keyHandle;
  }

  /**
   * This is a X.509 certificate.
   */
  public X509Certificate getAttestationCertificate() {
    return attestationCertificate;
  }

  /** This is a ECDSA signature (on P-256) */
  public byte[] getSignature() {
    return signature;
  }

  @Override
  public int hashCode() {
    return Objects.hash(userPublicKey, keyHandle, attestationCertificate, signature);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    RegisterResponse other = (RegisterResponse) obj;
    return Arrays.equals(userPublicKey, other.userPublicKey)
        && Arrays.equals(keyHandle, other.keyHandle)
        && Arrays.equals(signature, other.signature)
        && Objects.equals(attestationCertificate, other.attestationCertificate);
  }
}
