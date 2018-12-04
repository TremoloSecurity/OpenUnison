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

package com.google.u2f.server.data;

public class SignSessionData extends EnrollSessionData {
  private static final long serialVersionUID = -1374014642398686120L;

  private final byte[] publicKey;

  public SignSessionData(String accountName, String appId, byte[] challenge, byte[] publicKey) {
    super(accountName, appId, challenge);
    this.publicKey = publicKey;
  }

  public byte[] getPublicKey() {
    return publicKey;
  }
}
