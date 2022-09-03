/*
Copyright 2022 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.tremolosecurity.provisioning.core.providers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.joda.time.DateTime;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.kohsuke.github.GHOrganization;
import org.kohsuke.github.GHPersonSet;
import org.kohsuke.github.GHTeam;
import org.kohsuke.github.GHTeam.Privacy;
import org.kohsuke.github.GHTeamBuilder;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProviderWithAddGroup;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class GitHubProvider implements UserStoreProviderWithAddGroup {

	static Logger logger = Logger.getLogger(GitHubProvider.class.getName());
	
	Key githubAppKey;
	String appid;
	String orgName;

	String accessTokensUrl;
	JSONObject permissions;

	String token;
	DateTime expires;

	
	String name;
	
	String apiHost;
	
	public String getApiHost() {
		return apiHost;
	}

	@Override
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		throw new ProvisioningException("Not implemented");

	}

	@Override
	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Not implemented");

	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			this.genToken();
			GitHub github = new GitHubBuilder().withOAuthToken(this.token).withEndpoint(this.apiHost).build();
			
			GHUser fromGithub = github.getUser(user.getUserID());
			if (fromGithub == null) {
				throw new ProvisioningException("Can not create user " + user.getUserID());
			}
			
			GHOrganization org = github.getOrganization(this.orgName);
			
			List<String> currentGroups = this.loadGroupsForUser(user.getUserID());
			HashSet<String> userGroups = new HashSet<String>();
			userGroups.addAll(currentGroups);
			
			for (String group : user.getGroups()) {
				if (! userGroups.contains(group)) {
					GHTeam team = org.getTeamByName(group);
					if (team != null) {
						team.add(fromGithub);
						GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Add,  approvalID, workflow, "group", group);
					} else {
						logger.warn("Team " + group + " does not exist in the organization " + this.orgName);
					}
				}
			}
			
			if (! addOnly) {
				userGroups.clear();
				userGroups.addAll(user.getGroups());
				for (String group : currentGroups) {
					if (! userGroups.contains(group)) {
						GHTeam team = org.getTeamByName(group);
						if (team != null) {
							team.remove(fromGithub);
							GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,false, ActionType.Delete,  approvalID, workflow, "group", group);
						} else {
							logger.warn("Team " + group + " does not exist in the organization " + this.orgName);
						}
					}
				}
			}
			
		} catch (JoseException | IOException | ProvisioningException | ParseException e) {
			throw new ProvisioningException("Could not sync user",e);
		}
		
		

	}

	@Override
	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Not implemented");

	}

	public String getToken() throws ClientProtocolException, JoseException, IOException, ProvisioningException, ParseException {
		this.genToken();
		return this.token;
	}
	
	private void genToken()
			throws JoseException, ClientProtocolException, IOException, ProvisioningException, ParseException {

		synchronized (this.expires) {

			if (this.expires.isBeforeNow()) {

				// geenrate app token

				JwtClaims claims = new JwtClaims();
				claims.setIssuer(appid); // who creates the token and signs it

				claims.setExpirationTimeMinutesInTheFuture(8); // time when the token will expire (10 minutes from now)
				claims.setNotBeforeMinutesInThePast(1);
				claims.setGeneratedJwtId(); // a unique identifier for the token
				claims.setIssuedAtToNow(); // when the

				JsonWebSignature jws = new JsonWebSignature();
				jws.setPayload(claims.toJson());
				jws.setKey(this.githubAppKey);
				jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

				String appJwt = jws.getCompactSerialization();

				

				BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
						GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
				RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
				CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc)
						.build();

				try {
					HttpGet get = new HttpGet(this.apiHost + "/app/installations");
					get.addHeader("Authorization", "Bearer " + appJwt);
					get.addHeader("Accept", "application/vnd.github+json");
	
					CloseableHttpResponse httpResp = http.execute(get);
	
					String respTxt = EntityUtils.toString(httpResp.getEntity());
					
	
					JSONParser parser = new JSONParser();
	
					if (httpResp.getStatusLine().getStatusCode() == 200) {
						JSONArray installs = (JSONArray) parser.parse(respTxt);
						for (Object o : installs) {
							JSONObject install = (JSONObject) o;
							JSONObject account = (JSONObject) install.get("account");
	
							String org = (String) account.get("login");
							if (org.equals(this.orgName)) {
								accessTokensUrl = (String) install.get("access_tokens_url");
								permissions = (JSONObject) install.get("permissions");
							}
						}
	
						if (this.accessTokensUrl == null) {
							throw new ProvisioningException("Org " + this.orgName + " has no installatiosn");
						}
	
						JSONObject root = new JSONObject();
						root.put("permissions", permissions);
	
						HttpUriRequest loadtokens = RequestBuilder.post()
								.addHeader(new BasicHeader("Authorization", "Bearer " + appJwt))
								.addHeader(new BasicHeader("Accept", "application/vnd.github+json"))
								.setUri(this.accessTokensUrl).setEntity(new StringEntity(root.toString())).build();
	
						httpResp = http.execute(loadtokens);
	
						respTxt = EntityUtils.toString(httpResp.getEntity());
	
						if (httpResp.getStatusLine().getStatusCode() == 201) {
							root = (JSONObject) parser.parse(respTxt);
							this.token = (String) root.get("token");
	
							String expiresTS = (String) root.get("expires_at");
							DateTime local = DateTime.parse(expiresTS);
							this.expires = local.minusMillis(5);
						} else {
							throw new ProvisioningException(
									"Could not load tokens:" + httpResp.getStatusLine().getStatusCode() + " / " + respTxt);
						}
	
					} else {
						throw new ProvisioningException("Could not load installations:"
								+ httpResp.getStatusLine().getStatusCode() + " / " + respTxt);
					}
				} finally {
					if (http != null) {
						http.close();
					}
					
					if (bhcm != null) { 
						bhcm.shutdown();
					}
				}
			}

		}

	}

	@Override
	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		try {
			this.genToken();
			GitHub github = new GitHubBuilder().withOAuthToken(this.token).withEndpoint(this.apiHost).build();
			GHUser fromGitHub = github.getUser(userID);

			if (fromGitHub == null) {
				return null;
			}

			User user = new User(userID);

			user.getAttribs().put("login", new Attribute("login", userID));

			if (attributes.contains("email") && fromGitHub.getEmail() != null && !fromGitHub.getEmail().isEmpty()) {
				user.getAttribs().put("email", new Attribute("email", fromGitHub.getEmail()));
			}

			if (attributes.contains("name") && fromGitHub.getName() != null && !fromGitHub.getName().isEmpty()) {
				user.getAttribs().put("name", new Attribute("name", fromGitHub.getName()));

			}

			if (attributes.contains("location") && fromGitHub.getLocation() != null
					&& !fromGitHub.getLocation().isEmpty()) {
				user.getAttribs().put("location", new Attribute("location", fromGitHub.getLocation()));
			}

			if (attributes.contains("company") && fromGitHub.getCompany() != null
					&& !fromGitHub.getCompany().isEmpty()) {
				user.getAttribs().put("company", new Attribute("company", fromGitHub.getCompany()));
			}

			if (attributes.contains("organizations")) {
				Attribute orgs = new Attribute("organizations");

				for (GHOrganization org : fromGitHub.getOrganizations()) {
					orgs.getValues().add(org.getName());
				}

				user.getAttribs().put("organizations", orgs);
			}
			
			
			
			user.getGroups().addAll(loadGroupsForUser(userID));
			
			
			

			return user;
		} catch (IOException | JoseException | ParseException e) {
			throw new ProvisioningException("Could not load github login '" + userID + "'", e);
		}

	}

	private List<String> loadGroupsForUser(String userID)
			throws UnsupportedEncodingException, IOException, ClientProtocolException, ParseException {
		List<String> groups = new ArrayList<String>();
		String groupsGraphQuery = String.format("query {organization(login: \"%s\") {teams(first: 100, userLogins: [\"%s\"]) {totalCount edges { node { name description  } } } } }",this.orgName,userID);
		
		JSONObject root = new JSONObject();
		root.put("query", groupsGraphQuery);
		
		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
		CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc)
				.build();
		try {
			HttpUriRequest graphql = RequestBuilder.post()
					.addHeader(new BasicHeader("Authorization","Bearer " + this.token))
					.setUri(this.apiHost + "/graphql")
					.setEntity(new StringEntity(root.toString())).build();
	
			
			CloseableHttpResponse httpResp = http.execute(graphql);
			
			String respTxt = EntityUtils.toString(httpResp.getEntity());
			
			if (httpResp.getStatusLine().getStatusCode() == 200) {
				JSONParser parser = new JSONParser();
				root = (JSONObject) parser.parse(respTxt);
				JSONObject data = (JSONObject) root.get("data");
				if (data != null) {
					JSONObject orgs = (JSONObject) data.get("organization");
					if (orgs != null) {
						JSONObject teams = (JSONObject) orgs.get("teams");
						if (teams != null) {
							JSONArray edges = (JSONArray) teams.get("edges");
							for (Object o : edges) {
								JSONObject edge = (JSONObject) o;
								JSONObject node = (JSONObject) edge.get("node");
								if (node != null) {
									groups.add((String)node.get("name"));
								}
							}
						}
					}
				}
			} else {
				logger.warn("Could not load groups for " + userID + ": " + httpResp.getStatusLine().getStatusCode() + " / " + respTxt);
			}
		} finally {
			if (http != null) {
				http.close();
			}
			
			if (bhcm != null) {
				bhcm.close();
			}
		}
		
		
		
		return groups;
	}

	@Override
	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.name = name;
		String b64Key = cfg.get("githubAppKey").getValues().get(0);

		PEMParser pemParser = new PEMParser(
				new InputStreamReader(new ByteArrayInputStream(Base64.getDecoder().decode(b64Key))));
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		try {

			KeyPair kp = converter.getKeyPair((PEMKeyPair) pemParser.readObject());
			this.githubAppKey = kp.getPrivate();
		} catch (IOException e1) {
			throw new ProvisioningException("Could not decode GitHub app key", e1);
		}

		this.appid = cfg.get("appid").getValues().get(0);
		this.orgName = cfg.get("org").getValues().get(0);
		
		if (cfg.get("apiHost") != null) {
			this.apiHost = cfg.get("apiHost").getValues().get(0);
		} else {
			this.apiHost = "api.github.com";
		}
		
		this.apiHost = "https://" + this.apiHost;

		// allways start expired
		this.expires = DateTime.now().minusMonths(1);
		/*
		 * 
		 * try { this.github = new
		 * GitHubBuilder().withOAuthToken(cfg.get("token").getValues().get(0)).build();
		 * } catch (IOException e) { throw new
		 * ProvisioningException("Could not initialize GitHub connection",e); }
		 * 
		 */

	}

	@Override
	public void shutdown() throws ProvisioningException {

	}

	@Override
	public void addGroup(String name, Map<String, String> additionalAttributes, User user, Map<String, Object> request)
			throws ProvisioningException {
		
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			this.genToken();
		} catch (JoseException | IOException | ProvisioningException | ParseException e) {
			throw new ProvisioningException("Could not load GitHub token",e);
		}
		
		try {
			GitHub github = new GitHubBuilder().withOAuthToken(this.token).build();
			
			GHOrganization ghorg = github.getOrganization(this.orgName);
			
			GHTeamBuilder teamBuilder = ghorg.createTeam(name);
			
			if (additionalAttributes.containsKey("description")) {
				teamBuilder.description(additionalAttributes.get("description"));
			}
			
			if (additionalAttributes.containsKey("privacy") && additionalAttributes.get("privacy").equals("secret")) {
				teamBuilder.privacy(Privacy.SECRET);
			} else {
				teamBuilder.privacy(Privacy.CLOSED);
			}
			
			teamBuilder.create();
			
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,true, ActionType.Add,  approvalID, workflow, "group-object", name);
			
			
		} catch (IOException e) {
			throw new ProvisioningException("Could not add group",e);
		}
		

	}

	@Override
	public void deleteGroup(String name, User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			this.genToken();
		} catch (JoseException | IOException | ProvisioningException | ParseException e) {
			throw new ProvisioningException("Could not load GitHub token",e);
		}
		
		try {
			GitHub github = new GitHubBuilder().withOAuthToken(this.token).build();
			
			GHOrganization ghorg = github.getOrganization(this.orgName);
			
			GHTeam team = ghorg.getTeamByName(name);
			
			if (team != null) {
				team.delete();
				GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().logAction(this.name,true, ActionType.Delete,  approvalID, workflow, "group-object", name);
			}
			
			
		} catch (IOException e) {
			throw new ProvisioningException("Could not add group",e);
		}

	}

	@Override
	public boolean isGroupExists(String name, User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			this.genToken();
		} catch (JoseException | IOException | ProvisioningException | ParseException e) {
			throw new ProvisioningException("Could not load GitHub token",e);
		}
		
		try {
			GitHub github = new GitHubBuilder().withOAuthToken(this.token).build();
			
			GHOrganization ghorg = github.getOrganization(this.orgName);
			
			GHTeam team = ghorg.getTeamByName(name);
			
			return team != null;
			
			
		} catch (IOException e) {
			throw new ProvisioningException("Could not add group",e);
		}
		
		
	}
	
	public GHOrganization getOrganization() throws ProvisioningException {
		try {
			this.genToken();
		} catch (JoseException | IOException | ProvisioningException | ParseException e) {
			throw new ProvisioningException("Could not load GitHub token",e);
		}
		
		try {
			GitHub github = new GitHubBuilder().withOAuthToken(this.token).build();
			
			GHOrganization ghorg = github.getOrganization(this.orgName);
			
			return ghorg;
			
			
		} catch (IOException e) {
			throw new ProvisioningException("Could not add group",e);
		}
	}

	public String getOrgName() {
		return orgName;
	}
	
	

}
