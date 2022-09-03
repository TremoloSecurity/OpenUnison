/*******************************************************************************
 * Copyright 2022 Tremolo Security, Inc.
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

package com.tremolosecurity.provisioning.customTasks.github.secrets;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.List;

import org.jose4j.lang.JoseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Key;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.providers.GitHubProvider;
import com.tremolosecurity.provisioning.util.HttpCon;

public class SecretManagement {
	GitHubProvider github;
	
	LazySodiumJava lazySodium;
	
	
	public SecretManagement(GitHubProvider github) {
		this.github = github;
		
		lazySodium = new LazySodiumJava(new SodiumJava(System.getenv("LIB_SODIUM_PATH")));
		
	}
	
	public List<String> getRepositorySecretNames(String repoName) throws ProvisioningException {
		
		List<String> secretNames = new ArrayList<String>();
		
		HttpRequest request;
		try {
			request = HttpRequest.newBuilder()
					  .uri(new URI(String.format("%s/repos/%s/%s/actions/secrets", github.getApiHost(),github.getOrgName(),repoName)))
					  .header("Authorization", String.format("Bearer %s", github.getToken()))
					  .GET()
					  .build();
			HttpClient client = HttpClient.newBuilder()
			        .version(Version.HTTP_1_1).build();
			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
			
			if (response.statusCode() != 200) {
				throw new ProvisioningException(String.format("Could not list secrets in %s/%s: %d / %s",this.github.getOrgName(),repoName,response.statusCode(),response.body()));
			}
			
			JSONObject root = (JSONObject) new JSONParser().parse(response.body());
			JSONArray secrets = (JSONArray) root.get("secrets");
			for (Object o : secrets) {
				JSONObject secret = (JSONObject) o;
				secretNames.add((String)secret.get("name"));
			}
		} catch (URISyntaxException | JoseException | IOException | ProvisioningException | ParseException | InterruptedException e) {
			throw new ProvisioningException(String.format("Could not list secrets in %s/%s",this.github.getOrgName(),repoName),e);
		}
		
		
		
		
		return secretNames;
		
	}
	
	public void storeSecret(String repoName,String name,String value) throws ProvisioningException, SodiumException {
		String publicKeyB64;
		String keyid;
		
		
		// first get the public key
		HttpRequest request;
		try {
			request = HttpRequest.newBuilder()
					  .uri(new URI(String.format("%s/repos/%s/%s/actions/secrets/public-key", github.getApiHost(),github.getOrgName(),repoName)))
					  .header("Authorization", String.format("Bearer %s", github.getToken()))
					  .GET()
					  .build();
			HttpClient client = HttpClient.newBuilder()
			        .version(Version.HTTP_1_1).build();
			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
			
			if (response.statusCode() != 200) {
				throw new ProvisioningException(String.format("Could not list secrets in %s/%s: %d / %s",this.github.getOrgName(),repoName,response.statusCode(),response.body()));
			}
			
			JSONObject root = (JSONObject) new JSONParser().parse(response.body());
			publicKeyB64 = (String) root.get("key");
			keyid = (String) root.get("key_id");
			
		} catch (URISyntaxException | JoseException | IOException | ProvisioningException | ParseException | InterruptedException e) {
			throw new ProvisioningException(String.format("Could not list secrets in %s/%s",this.github.getOrgName(),repoName),e);
		}
		
		byte[] key = java.util.Base64.getDecoder().decode(publicKeyB64);
		
		Key pkey = Key.fromBytes(key);
		
		byte[] enc = this.lazySodium.sodiumHex2Bin(this.lazySodium.cryptoBoxSealEasy(value, pkey));
		
		String encB64 = java.util.Base64.getEncoder().encodeToString(enc);
		
		JSONObject newSecret = new JSONObject();
		newSecret.put("key_id", keyid);
		newSecret.put("encrypted_value", encB64);
		
		try {
			request = HttpRequest.newBuilder()
					  .uri(new URI(String.format("%s/repos/%s/%s/actions/secrets/%s", github.getApiHost(),github.getOrgName(),repoName,name)))
					  .header("Authorization", String.format("Bearer %s", github.getToken()))
					  .PUT(HttpRequest.BodyPublishers.ofString(newSecret.toString()))
					  .build();
			HttpClient client = HttpClient.newBuilder()
			        .version(Version.HTTP_1_1).build();
			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
			
			if (response.statusCode() != 201 && response.statusCode() != 204) {
				throw new ProvisioningException(String.format("Could not create secrets in %s/%s: %d / %s",this.github.getOrgName(),repoName,response.statusCode(),response.body()));
			}
			
			
			
		} catch (URISyntaxException | JoseException | IOException | ProvisioningException | ParseException | InterruptedException e) {
			throw new ProvisioningException(String.format("Could not create secrets %s in %s/%s",name,this.github.getOrgName(),repoName),e);
		}
	}
}
