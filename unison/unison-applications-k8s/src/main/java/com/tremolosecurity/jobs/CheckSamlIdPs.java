package com.tremolosecurity.jobs;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.quartz.JobExecutionContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class CheckSamlIdPs extends UnisonJob {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CheckSamlIdPs.class.getName());

	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {
		if (logger.isDebugEnabled()) logger.debug("Checking IdPs");
		String selfLink = context.getJobDetail().getJobDataMap().getString("selfLink");
		if (logger.isDebugEnabled()) logger.debug("Self Link : '" + selfLink + "'");
		String targetName = context.getJobDetail().getJobDataMap().getString("target");
		if (logger.isDebugEnabled()) logger.debug("Target : '" + targetName + "'");
		
		OpenShiftTarget target = (OpenShiftTarget) configManager.getProvisioningEngine().getTarget(targetName).getProvider();
		
		HttpCon con = null;
		try {
			con = target.createClient();
			String rawJson = target.callWS(target.getAuthToken(), con, selfLink);
			if (logger.isDebugEnabled()) logger.debug("JSON : '" + rawJson + "'");
			JSONParser parser = new JSONParser();
			JSONObject ouCr = (JSONObject) parser.parse(rawJson);
			JSONObject spec = (JSONObject) ouCr.get("spec");
			JSONObject status = (JSONObject) ouCr.get("status"); 
			JSONObject fingerPrints = (JSONObject) status.get("idpCertificateFingerprints");
					
			JSONArray remoteIdps = (JSONArray) spec.get("saml_remote_idp");
			for (Object o : remoteIdps) {
				if (logger.isDebugEnabled()) logger.debug("Checking IdP");
				JSONObject idpCfg = (JSONObject) o;
				JSONObject source = (JSONObject) idpCfg.get("source");
				
				String url = (String) source.get("url");
				if (logger.isDebugEnabled())  logger.debug("URL : '" + url + "'");
				
				if (url != null) {
					if (logger.isDebugEnabled()) logger.debug("Pulling metadata");
					String metadataXml = this.downloadFile(url,con.getHttp());
					
					DocumentBuilderFactory dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
			        dbFactory.setNamespaceAware(true);
					DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
					Document doc = dBuilder.parse(new java.io.ByteArrayInputStream(metadataXml.getBytes("UTF-8")));
					XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();
					
					Element ed = (Element) xpath.compile("/*[local-name() = 'EntityDescriptor']").evaluate(doc,javax.xml.xpath.XPathConstants.NODE);
			        
			        
			        String entityId = ed.getAttribute("entityID");
			        List<String> sigCerts = new ArrayList<String>();
			        
			        String xpathexpr = "//*[local-name() = 'IDPSSODescriptor']";
			        Element idp = (Element) xpath.compile(xpathexpr).evaluate(ed,javax.xml.xpath.XPathConstants.NODE);
			        
			        xpathexpr = "//*[local-name() = 'KeyDescriptor']";
			        NodeList keys = (NodeList) xpath.compile(xpathexpr).evaluate(idp,javax.xml.xpath.XPathConstants.NODESET);
			        
			        for (int i = 0;i<keys.getLength();i++) {
			        	Element key = (Element) keys.item(i);
			        	if (key.getAttribute("use").equalsIgnoreCase("signing")) {
			        		xpathexpr = "//*[local-name() = 'X509Certificate']";
			                Element certTag = (Element) xpath.compile(xpathexpr).evaluate(key,javax.xml.xpath.XPathConstants.NODE);
			                logger.debug(certTag.getTextContent());
			                sigCerts.add(certTag.getTextContent());
			        	}
			        }
			        
			        
			        
			      

			        
			        
			        MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
			        int i = 0;
			        for (String certStr : sigCerts) {
		                X509Certificate currentCert = string2cert(certStr);
		                if (logger.isDebugEnabled()) {
		                	logger.debug("Cert " + i + "  : " + currentCert.getSubjectDN());
		                }
		                i++;
		                digest.update(currentCert.getEncoded(),0,currentCert.getEncoded().length);
		            }
			        
			        
			        byte[] digest_bytes = digest.digest();
			        String digest_base64 = java.util.Base64.getEncoder().encodeToString(digest_bytes);
			        String digestFromStatus = (String) fingerPrints.get(entityId);
			        
			        if (logger.isDebugEnabled()) logger.debug("Digest from Metadata : '" + digest_base64 + "'");
			        if (logger.isDebugEnabled()) logger.debug("Digest from status : '" + digestFromStatus + "'");
			        
			        if (! digest_base64.equals(digestFromStatus)) {
			        	JSONObject patch = new JSONObject();
			        	JSONObject metaData = new JSONObject();
			        	patch.put("metadata", metaData);
			        	JSONObject annotations = new JSONObject();
			        	metaData.put("annotations", annotations);
			        	annotations.put("tremolo.io/samlupdate", new DateTime().toString());
			        	
			        	String jsonPatch = patch.toJSONString();
			        	logger.info("Patching OpenUnison CR");
			        	target.callWSPatchJson(target.getAuthToken(), con, selfLink, jsonPatch);
			        	return;
			        	
			        }
			        
				}
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not check idps",e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				con.getBcm().close();
			}
		}
		
		

	}
	
	private String downloadFile(String url, CloseableHttpClient http) throws IOException {
        HttpGet get = new HttpGet(url);
        HttpResponse resp = http.execute(get);
        try {
	        try (BufferedReader reader = new BufferedReader(new InputStreamReader(resp.getEntity().getContent(), StandardCharsets.UTF_8)))
	        {
	            return reader.lines().collect(Collectors.joining("\n"));
	        }
        } finally {
        	get.abort();
        }
    }
	
	private X509Certificate string2cert(String b64Cert) throws Exception {
        // System.out.println(b64Cert);
        // System.out.println("");
        b64Cert = b64Cert.replace("\n", "").trim();
        // System.out.println(b64Cert);
        ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(b64Cert));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        return (X509Certificate) c.iterator().next();
    }

}
