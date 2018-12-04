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

package com.google.u2f.server;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import com.google.u2f.server.data.EnrollSessionData;
import com.google.u2f.server.data.SecurityKeyData;
import com.google.u2f.server.data.SignSessionData;

public interface DataStore {

  // attestation certs and trust
  public void addTrustedCertificate(X509Certificate certificate);

  public Set<X509Certificate> getTrustedCertificates();


  // session handling
  public /* sessionId */ String storeSessionData(EnrollSessionData sessionData);

  public SignSessionData getSignSessionData(String sessionId);

  public EnrollSessionData getEnrollSessionData(String sessionId);


  // security key management
  public void addSecurityKeyData(String accountName, SecurityKeyData securityKeyData);

  public List<SecurityKeyData> getSecurityKeyData(String accountName);

  public void removeSecurityKey(String accountName, byte[] publicKey);

  public void updateSecurityKeyCounter(String accountName, byte[] publicKey, int newCounterValue);
}
