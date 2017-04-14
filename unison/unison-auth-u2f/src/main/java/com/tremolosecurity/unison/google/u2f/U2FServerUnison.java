/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
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

package com.tremolosecurity.unison.google.u2f;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.u2f.U2FConsts;
import com.google.u2f.U2FException;
import com.google.u2f.codec.RawMessageCodec;
import com.google.u2f.key.UserPresenceVerifier;
import com.google.u2f.key.messages.AuthenticateResponse;
import com.google.u2f.key.messages.RegisterResponse;
import com.google.u2f.server.ChallengeGenerator;
import com.google.u2f.server.Crypto;
import com.google.u2f.server.DataStore;
import com.google.u2f.server.U2FServer;
import com.google.u2f.server.data.EnrollSessionData;
import com.google.u2f.server.data.SecurityKeyData;
import com.google.u2f.server.data.SecurityKeyData.Transports;
import com.google.u2f.server.data.SignSessionData;
import com.google.u2f.server.impl.BouncyCastleCrypto;
import com.google.u2f.server.impl.attestation.u2f.U2fAttestation;
import com.google.u2f.server.messages.RegisteredKey;
import com.google.u2f.server.messages.RegistrationRequest;
import com.google.u2f.server.messages.RegistrationResponse;
import com.google.u2f.server.messages.SignResponse;
import com.google.u2f.server.messages.U2fSignRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

public class U2FServerUnison implements U2FServer {
  private static final String TYPE_PARAM = "typ";
  private static final String CHALLENGE_PARAM = "challenge";
  private static final String ORIGIN_PARAM = "origin";

  // TODO: use these for channel id checks in verifyBrowserData
  @SuppressWarnings("unused")
  private static final String CHANNEL_ID_PARAM = "cid_pubkey";

  @SuppressWarnings("unused")
  private static final String UNUSED_CHANNEL_ID = "";

  private static final org.apache.logging.log4j.Logger log = org.apache.logging.log4j.LogManager.getLogger(U2FServerUnison.class.getName());

  private final ChallengeGenerator challengeGenerator;
  private final DataStore dataStore;
  private final Crypto crypto;
  private final Set<String> allowedOrigins;
  private boolean requireAttestation;

  public U2FServerUnison(ChallengeGenerator challengeGenerator, DataStore dataStore,
      Crypto crypto, Set<String> origins) {
    this(challengeGenerator,dataStore,crypto,origins,false);
    
  }

  public U2FServerUnison(ChallengeGenerator challengeGenerator, DataStore dataStore,
	      Crypto crypto, Set<String> origins, boolean requireAttestation) {
	  this.challengeGenerator = challengeGenerator;
	    this.dataStore = dataStore;
	    this.crypto = crypto;
	    this.allowedOrigins = canonicalizeOrigins(origins);
	    this.requireAttestation = requireAttestation;
  }

@Override
  public RegistrationRequest getRegistrationRequest(String accountName, String appId) {
    log.debug(">> getRegistrationRequest " + accountName);

    byte[] challenge = challengeGenerator.generateChallenge(accountName);
    EnrollSessionData sessionData = new EnrollSessionData(accountName, appId, challenge);

    String sessionId = dataStore.storeSessionData(sessionData);

    String challengeBase64 = Base64.encodeBase64URLSafeString(challenge);

    if (log.isDebugEnabled()) {
	    log.debug("-- Output --");
	    log.debug("  sessionId: " + sessionId);
	    log.debug("  challenge: " + Hex.encodeHexString(challenge));
	
	    log.debug("<< getRegistrationRequest " + accountName);
    }
    return new RegistrationRequest(U2FConsts.U2F_V2, challengeBase64, appId, sessionId);
  }

  @Override
  public SecurityKeyData processRegistrationResponse(
      RegistrationResponse registrationResponse, long currentTimeInMillis) throws U2FException {
    log.debug(">> processRegistrationResponse");

    String sessionId = registrationResponse.getSessionId();
    String clientDataBase64 = registrationResponse.getClientData();
    String rawRegistrationDataBase64 = registrationResponse.getRegistrationData();

    log.debug(">> rawRegistrationDataBase64: " + rawRegistrationDataBase64);
    EnrollSessionData sessionData = dataStore.getEnrollSessionData(sessionId);

    if (sessionData == null) {
      throw new U2FException("Unknown session_id");
    }

    String appId = sessionData.getAppId();
    String clientData = new String(Base64.decodeBase64(clientDataBase64));
    byte[] rawRegistrationData = Base64.decodeBase64(rawRegistrationDataBase64);
    if (log.isDebugEnabled()) {
	    log.debug("-- Input --");
	    log.debug("  sessionId: " + sessionId);
	    log.debug("  challenge: " + Hex.encodeHexString(sessionData.getChallenge()));
	    log.debug("  accountName: " + sessionData.getAccountName());
	    log.debug("  clientData: " + clientData);
	    log.debug("  rawRegistrationData: " + Hex.encodeHexString(rawRegistrationData));
    }
    RegisterResponse registerResponse = RawMessageCodec.decodeRegisterResponse(rawRegistrationData);

    byte[] userPublicKey = registerResponse.getUserPublicKey();
    byte[] keyHandle = registerResponse.getKeyHandle();
    X509Certificate attestationCertificate = registerResponse.getAttestationCertificate();
    byte[] signature = registerResponse.getSignature();
    List<Transports> transports = null;
    try {
      transports = U2fAttestation.Parse(attestationCertificate).getTransports();
    } catch (CertificateParsingException e) {
      log.warn("Could not parse transports extension " + e.getMessage());
    }

    if (log.isDebugEnabled()) {
	    log.debug("-- Parsed rawRegistrationResponse --");
	    log.debug("  userPublicKey: " + Hex.encodeHexString(userPublicKey));
	    log.debug("  keyHandle: " + Hex.encodeHexString(keyHandle));
	    log.debug("  attestationCertificate: " + attestationCertificate.toString());
	    log.debug("  transports: " + transports);
	    try {
	      log.debug("  attestationCertificate bytes: "
	          + Hex.encodeHexString(attestationCertificate.getEncoded()));
	    } catch (CertificateEncodingException e) {
	      throw new U2FException("Cannot encode certificate", e);
	    }
	    log.debug("  signature: " + Hex.encodeHexString(signature));
    }
    
    byte[] appIdSha256 = crypto.computeSha256(appId.getBytes());
    byte[] clientDataSha256 = crypto.computeSha256(clientData.getBytes());
    byte[] signedBytes = RawMessageCodec.encodeRegistrationSignedBytes(
        appIdSha256, clientDataSha256, keyHandle, userPublicKey);

    Set<X509Certificate> trustedCertificates = dataStore.getTrustedCertificates();
    boolean found = false;
    for (X509Certificate trusted : trustedCertificates) {
    	try {
			attestationCertificate.verify(trusted.getPublicKey());
			found = true;
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			
		}
    }
    
    if (!found) {
    	if (! this.requireAttestation) {
    		log.warn("attestion cert is not trusted");
    	} else {
    		throw new U2FException("Attestation certificate is not trusted");
    	}
    }

    verifyBrowserData(
        new JsonParser().parse(clientData), "navigator.id.finishEnrollment", sessionData);
    if (log.isDebugEnabled()) {
    	log.debug("Verifying signature of bytes " + Hex.encodeHexString(signedBytes));
    }
    
    if (!crypto.verifySignature(attestationCertificate, signedBytes, signature)) {
      throw new U2FException("Signature is invalid");
    }

    // The first time we create the SecurityKeyData, we set the counter value to 0.
    // We don't actually know what the counter value of the real device is - but it will
    // be something bigger (or equal) to 0, so subsequent signatures will check out ok.
    SecurityKeyData securityKeyData = new SecurityKeyData(currentTimeInMillis, transports,
        keyHandle, userPublicKey, attestationCertificate, /* initial counter value */ 0);
    dataStore.addSecurityKeyData(sessionData.getAccountName(), securityKeyData);

    if (log.isDebugEnabled()) {
    	log.debug("<< processRegistrationResponse");
    }
    
    return securityKeyData;
  }

  @Override
  public U2fSignRequest getSignRequest(String accountName, String appId) throws U2FException {
	  if (log.isDebugEnabled()) {
		  log.debug(">> getSignRequest " + accountName);
	  }

    List<SecurityKeyData> securityKeyDataList = dataStore.getSecurityKeyData(accountName);

    byte[] challenge = challengeGenerator.generateChallenge(accountName);
    String challengeBase64 = Base64.encodeBase64URLSafeString(challenge);

    ImmutableList.Builder<RegisteredKey> registeredKeys = ImmutableList.builder();
    if (log.isDebugEnabled()) {
    	log.debug("  challenge: " + Hex.encodeHexString(challenge));
    }
    
    for (SecurityKeyData securityKeyData : securityKeyDataList) {
      SignSessionData sessionData =
          new SignSessionData(accountName, appId, challenge, securityKeyData.getPublicKey());
      String sessionId = dataStore.storeSessionData(sessionData);

      byte[] keyHandle = securityKeyData.getKeyHandle();
      List<Transports> transports = securityKeyData.getTransports();
      if (log.isDebugEnabled()) {
	      log.debug("-- Output --");
	      log.debug("  sessionId: " + sessionId);
	      log.debug("  keyHandle: " + Hex.encodeHexString(keyHandle));
      }
      String keyHandleBase64 = Base64.encodeBase64URLSafeString(keyHandle);
      
      if (log.isDebugEnabled()) {
    	  log.debug("<< getRegisteredKey " + accountName);
      }
      
      registeredKeys.add(
          new RegisteredKey(U2FConsts.U2F_V2, keyHandleBase64, transports, appId, sessionId));
    }

    return new U2fSignRequest(challengeBase64, registeredKeys.build());
  }

  @Override
  public SecurityKeyData processSignResponse(SignResponse signResponse) throws U2FException {
	  if (log.isDebugEnabled()) {
		  log.debug(">> processSignResponse");
	  }

    String sessionId = signResponse.getSessionId();
    String browserDataBase64 = signResponse.getClientData();
    String rawSignDataBase64 = signResponse.getSignatureData();

    SignSessionData sessionData = dataStore.getSignSessionData(sessionId);

    if (sessionData == null) {
      throw new U2FException("Unknown session_id");
    }

    String appId = sessionData.getAppId();
    SecurityKeyData securityKeyData = null;

    for (SecurityKeyData temp : dataStore.getSecurityKeyData(sessionData.getAccountName())) {
      if (Arrays.equals(sessionData.getPublicKey(), temp.getPublicKey())) {
        securityKeyData = temp;
        break;
      }
    }

    if (securityKeyData == null) {
      throw new U2FException("No security keys registered for this user");
    }

    String browserData = new String(Base64.decodeBase64(browserDataBase64));
    byte[] rawSignData = Base64.decodeBase64(rawSignDataBase64);

    if (log.isDebugEnabled()) {
	    log.debug("-- Input --");
	    log.debug("  sessionId: " + sessionId);
	    log.debug("  publicKey: " + Hex.encodeHexString(securityKeyData.getPublicKey()));
	    log.debug("  challenge: " + Hex.encodeHexString(sessionData.getChallenge()));
	    log.debug("  accountName: " + sessionData.getAccountName());
	    log.debug("  browserData: " + browserData);
	    log.debug("  rawSignData: " + Hex.encodeHexString(rawSignData));
    }
    verifyBrowserData(
        new JsonParser().parse(browserData), "navigator.id.getAssertion", sessionData);

    AuthenticateResponse authenticateResponse =
        RawMessageCodec.decodeAuthenticateResponse(rawSignData);
    byte userPresence = authenticateResponse.getUserPresence();
    int counter = authenticateResponse.getCounter();
    byte[] signature = authenticateResponse.getSignature();

    if (log.isDebugEnabled()) {
	    log.debug("-- Parsed rawSignData --");
	    log.debug("  userPresence: " + Integer.toHexString(userPresence & 0xFF));
	    log.debug("  counter: " + counter);
	    log.debug("  signature: " + Hex.encodeHexString(signature));
    }

    if ((userPresence & UserPresenceVerifier.USER_PRESENT_FLAG) == 0) {
      throw new U2FException("User presence invalid during authentication");
    }

    if (counter <= securityKeyData.getCounter()) {
      throw new U2FException("Counter value smaller than expected!");
    }

    byte[] appIdSha256 = crypto.computeSha256(appId.getBytes());
    byte[] browserDataSha256 = crypto.computeSha256(browserData.getBytes());
    byte[] signedBytes = RawMessageCodec.encodeAuthenticateSignedBytes(
        appIdSha256, userPresence, counter, browserDataSha256);

    if (log.isDebugEnabled()) {
    	log.debug("Verifying signature of bytes " + Hex.encodeHexString(signedBytes));
    }
    
    if (!crypto.verifySignature(
            crypto.decodePublicKey(securityKeyData.getPublicKey()), signedBytes, signature)) {
      throw new U2FException("Signature is invalid");
    }

    dataStore.updateSecurityKeyCounter(
        sessionData.getAccountName(), securityKeyData.getPublicKey(), counter);

    if (log.isDebugEnabled()) {
    	log.debug("<< processSignResponse");
    }
    return securityKeyData;
  }

  private void verifyBrowserData(JsonElement browserDataAsElement, String messageType,
      EnrollSessionData sessionData) throws U2FException {
    if (!browserDataAsElement.isJsonObject()) {
      throw new U2FException("browserdata has wrong format");
    }

    JsonObject browserData = browserDataAsElement.getAsJsonObject();

    // check that the right "typ" parameter is present in the browserdata JSON
    if (!browserData.has(TYPE_PARAM)) {
      throw new U2FException("bad browserdata: missing 'typ' param");
    }

    String type = browserData.get(TYPE_PARAM).getAsString();
    if (!messageType.equals(type)) {
      throw new U2FException("bad browserdata: bad type " + type);
    }

    // check that the right challenge is in the browserdata
    if (!browserData.has(CHALLENGE_PARAM)) {
      throw new U2FException("bad browserdata: missing 'challenge' param");
    }

    if (browserData.has(ORIGIN_PARAM)) {
      verifyOrigin(browserData.get(ORIGIN_PARAM).getAsString());
    }

    byte[] challengeFromBrowserData =
        Base64.decodeBase64(browserData.get(CHALLENGE_PARAM).getAsString());


    if (!Arrays.equals(challengeFromBrowserData, sessionData.getChallenge())) {
      throw new U2FException("wrong challenge signed in browserdata");
    }

    // TODO: Deal with ChannelID
  }

  private void verifyOrigin(String origin) throws U2FException {
    if (!allowedOrigins.contains(canonicalizeOrigin(origin))) {
      throw new U2FException(origin + " is not a recognized home origin for this backend"
          + Joiner.on(", ").join(allowedOrigins));
    }
  }

  @Override
  public List<SecurityKeyData> getAllSecurityKeys(String accountName) {
    return dataStore.getSecurityKeyData(accountName);
  }

  @Override
  public void removeSecurityKey(String accountName, byte[] publicKey) throws U2FException {
    dataStore.removeSecurityKey(accountName, publicKey);
  }

  private static Set<String> canonicalizeOrigins(Set<String> origins) {
    ImmutableSet.Builder<String> result = ImmutableSet.builder();
    for (String origin : origins) {
      result.add(canonicalizeOrigin(origin));
    }
    return result.build();
  }

  static String canonicalizeOrigin(String url) {
    URI uri;
    try {
      uri = new URI(url);
    } catch (URISyntaxException e) {
      throw new RuntimeException("specified bad origin", e);
    }
    return uri.getScheme() + "://" + uri.getAuthority();
  }
}
