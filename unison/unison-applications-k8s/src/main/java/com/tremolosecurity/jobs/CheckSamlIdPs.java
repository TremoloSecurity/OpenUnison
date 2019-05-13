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

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
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
		logger.info("Checking IdPs");
		String selfLink = context.getJobDetail().getJobDataMap().getString("selfLink");
		logger.info("Self Link : '" + selfLink + "'");
		String targetName = context.getJobDetail().getJobDataMap().getString("target");
		logger.info("Target : '" + targetName + "'");
		
		OpenShiftTarget target = (OpenShiftTarget) configManager.getProvisioningEngine().getTarget(targetName).getProvider();
		
		HttpCon con = null;
		try {
			con = target.createClient();
			String rawJson = target.callWS(target.getAuthToken(), con, selfLink);
			logger.info("JSON : '" + rawJson + "'");
			JSONParser parser = new JSONParser();
			JSONObject ouCr = (JSONObject) parser.parse(rawJson);
			JSONObject spec = (JSONObject) ouCr.get("spec");
			JSONObject status = (JSONObject) ouCr.get("status"); 
			JSONObject fingerPrints = (JSONObject) status.get("idpCertificateFingerprints");
					
			JSONArray remoteIdps = (JSONArray) spec.get("saml_remote_idp");
			for (Object o : remoteIdps) {
				logger.info("Checking IdP");
				JSONObject idpCfg = (JSONObject) o;
				JSONObject source = (JSONObject) idpCfg.get("source");
				
				String url = (String) source.get("url");
				logger.info("URL : '" + url + "'");
				
				if (url != null) {
					logger.info("Pulling metadata");
					String metadataXml = this.downloadFile(url);
					
					DocumentBuilderFactory dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
			        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			        Document doc = dBuilder.parse(new java.io.ByteArrayInputStream(metadataXml.getBytes("UTF-8")));
			        
			        String entityId = ((org.w3c.dom.Element) doc.getElementsByTagName("EntityDescriptor").item(0)).getAttribute("entityID");
			        Element idp = (Element) doc.getElementsByTagName("IDPSSODescriptor").item(0);
			        
			        X509Certificate currentCertChoice = null;
			        
			        NodeList keys = idp.getElementsByTagName("KeyDescriptor");
			        List<String> sigCerts = new ArrayList<String>();
			        
			        for (int i=0;i<keys.getLength();i++) {
			            Element key = (Element) keys.item(i);

			            if (key.getAttribute("use").equalsIgnoreCase("signing")) {
			                String sigCert = ((Element) ((Element)key.getElementsByTagName("KeyInfo").item(0)).getElementsByTagName("X509Data").item(0)).getElementsByTagName("X509Certificate").item(0).getTextContent();
			                sigCerts.add(sigCert);
			            }
			        }

			        if (sigCerts.size() == 1) {
			            currentCertChoice = string2cert(sigCerts.get(0));
			        } else {
			            for (String certStr : sigCerts) {
			                X509Certificate currentCert = string2cert(certStr);
			                if (currentCertChoice == null) {
			                	currentCertChoice = currentCert;
			                } else {
			                    if (currentCertChoice.getNotAfter().compareTo(currentCert.getNotAfter())  < 0  ) {
			                    	currentCertChoice = currentCert;
			                    }
			                }
			            }
			            
			        }
			        
			        MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
			        digest.update(currentCertChoice.getEncoded(),0,currentCertChoice.getEncoded().length);
			        byte[] digest_bytes = digest.digest();
			        String digest_base64 = java.util.Base64.getEncoder().encodeToString(digest_bytes);
			        String digestFromStatus = (String) fingerPrints.get(entityId);
			        
			        logger.info("Digest from Metadata : '" + digest_base64 + "'");
			        logger.info("Digest from status : '" + digestFromStatus + "'");
			        
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
	
	private String downloadFile(String url) throws IOException {
        URL urlObj = new URL(url);
        URLConnection conn = urlObj.openConnection();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)))
        {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
	
	private X509Certificate string2cert(String b64Cert) throws Exception {
        // System.out.println(b64Cert);
        // System.out.println("");
        b64Cert = b64Cert.replace("\n", "");
        // System.out.println(b64Cert);
        ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(b64Cert));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        return (X509Certificate) c.iterator().next();
    }

}
