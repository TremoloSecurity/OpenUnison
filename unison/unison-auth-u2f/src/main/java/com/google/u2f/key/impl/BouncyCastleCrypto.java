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

package com.google.u2f.key.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.u2f.U2FException;
import com.google.u2f.key.Crypto;

public class BouncyCastleCrypto implements Crypto {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  public byte[] sign(byte[] signedData, PrivateKey privateKey) throws U2FException {
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(privateKey);
      signature.update(signedData);
      return signature.sign();
    } catch (NoSuchAlgorithmException e) {
      throw new U2FException("Error when signing", e);
    } catch (SignatureException e) {
      throw new U2FException("Error when signing", e);
    } catch (InvalidKeyException e) {
      throw new U2FException("Error when signing", e);
    }
  }
}
