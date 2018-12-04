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

package com.google.u2f.server.messages;

import java.util.Objects;

public class SignResponse {

  /** websafe-base64 key handle from U2F device */
  private final String keyHandle;

  /** websafe-base64(client data) */
  private final String clientData;

  /** websafe-base64(raw response from U2F device) */
  private final String signatureData;

  /** session id originally passed */
  private final String sessionId;


  public SignResponse(String keyHandle, String signatureData, String clientData, String sessionId) {
    this.keyHandle = keyHandle;
    this.signatureData = signatureData;
    this.clientData = clientData;
    this.sessionId = sessionId;
  }

  public String getKeyHandle() {
    return keyHandle;
  }

  public String getClientData() {
    return clientData;
  }

  public String getSignatureData() {
    return signatureData;
  }

  public String getSessionId() {
    return sessionId;
  }

  @Override
  public int hashCode() {
    return Objects.hash(keyHandle, clientData, signatureData, sessionId);
  }

  @Override
  public boolean equals(Object obj) {
    if (getClass() != obj.getClass())
      return false;
    SignResponse other = (SignResponse) obj;
    return Objects.equals(keyHandle, other.keyHandle)
        && Objects.equals(clientData, other.clientData)
        && Objects.equals(signatureData, other.signatureData)
        && Objects.equals(sessionId, other.sessionId);
  }
}
