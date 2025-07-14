/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.auth;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.security.auth.x500.X500Principal;

import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.proxy.TremoloHttpSession;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;


import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.ssl.CRLManager;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;



public class CertAuth implements AuthMechanism {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CertAuth.class);
	
	ConfigManager cfgMgr;

	private ArrayList<CRLManager> crls;

	static final String[] SAN_NAMES = new String[] {"otherName","email","dNSName","x400Address","directoryName","ediPartyName","uniformResourceIdentifier","iPAddress","registeredID"};

	private ArrayList<CertificateExtractSubjectAttribute> extracts;
    

	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		Attribute issuersParam = authParams.get("issuer");
		HashSet<X500Principal> issuers = new HashSet<X500Principal>();
		for (String dn : issuersParam.getValues()) {
			issuers.add(new X500Principal(dn));
		}
		
		
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		X509Certificate[] certs = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
		
		if (certs == null) {
			if (amt.getRequired().equals("required")) {
				as.setSuccess(false);
				
			} 
			
			
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		}
		
		X509Certificate cert = certs[0];
		
		
		
		
		
		DN dn = new DN(cert.getSubjectX500Principal().getName());
		Vector<RDN> rdns = dn.getRDNs();
		
		HashMap<String,String> subject = new HashMap<String,String>();
		
		for (RDN rdn : rdns) {
			subject.put(rdn.getType(), rdn.getValue());
		}
		
		//Load SANS
		try {
			if (cert.getSubjectAlternativeNames() != null) {
				
				java.util.Collection altNames = cert.getSubjectAlternativeNames();
                Iterator iter = altNames.iterator();
                while (iter.hasNext()) {
                    java.util.List item = (java.util.List)iter.next();
                    Integer type = (Integer)item.get(0);
                    subject.put(SAN_NAMES[type.intValue()], item.get(1).toString());
                    
                    
                    
                    
                }
			}
		} catch (CertificateParsingException e1) {
			throw new ServletException("Could not parse certificate",e1);
		}
		
		for (CertificateExtractSubjectAttribute cesa : this.extracts) {
			cesa.addSubjects(subject, certs);
		}
		
		MyVDConnection myvd = cfgMgr.getMyVD();
		//HttpSession session = (HttpSession) req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		
		
		boolean OK = false;
		boolean certOK = true;
		int i = 0;
		for (X509Certificate certx : certs) {

			if (issuers.contains(certx.getIssuerX500Principal())) {

				OK = true;
			}
			
			
			if (certOK) {
				for (CRLManager crlM : this.crls) {
					X509Certificate issuer = null;
					if (i + 1 < certs.length) {
						issuer = certs[i + 1];
					} else {
						try {
							Enumeration<String> enumer = cfgMgr.getKeyStore().aliases();
							while (enumer.hasMoreElements()) {
								String alias = enumer.nextElement();
								X509Certificate lissuer = (X509Certificate) cfgMgr.getKeyStore().getCertificate(alias);
								if (lissuer != null && lissuer.getSubjectX500Principal().equals(certs[i].getIssuerX500Principal()) ) {
									try {
										certs[i].verify(lissuer.getPublicKey());
										issuer = lissuer;
									} catch (Exception e) {
										logger.warn("Issuer with wrong public key",e);
									}
									
								}
							}
						} catch (KeyStoreException e) {
							throw new ServletException("Could not process CRLs",e);
						}
					}
					
					if (issuer != null) {
						if (! crlM.isValid(certx,issuer)) {
							certOK = false;
							break;
						}
					} else {
						logger.warn("No issuer!  not performing CRL check");
					}
				}
			}
		}
		
		if (! OK || ! certOK) {
			as.setSuccess(false); 
			
			
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			return;
		}
		
		
		String uidAttr = "uid";
		if (authParams.get("uidAttr") != null) {
			uidAttr = authParams.get("uidAttr").getValues().get(0);
		}
		
		
		boolean uidIsFilter = false;
		if (authParams.get("uidIsFilter") != null) {
			uidIsFilter = authParams.get("uidIsFilter").getValues().get(0).equalsIgnoreCase("true");
		}
		
		String filter = "";
		if (uidIsFilter) {
			StringBuffer b = new StringBuffer();
			int lastIndex = 0;
			int index = uidAttr.indexOf('$');
			while (index >= 0) {
				b.append(uidAttr.substring(lastIndex,index));
				lastIndex = uidAttr.indexOf('}',index) + 1;
				String reqName = uidAttr.substring(index + 2,lastIndex - 1);
				b.append(subject.get(reqName));
				index = uidAttr.indexOf('$',index+1);
			}
			b.append(uidAttr.substring(lastIndex));
			filter = b.toString();
		
		} else {
			StringBuffer b = new StringBuffer();
			if (subject.get(uidAttr) == null) {
				filter = "(!(objectClass=*))";
			} else {
				filter = equal(uidAttr,subject.get(uidAttr)).toString();
			}
			
		}
		
		
		String rdnAttr = authParams.get("rdnAttribute").getValues().get(0);
		
		ArrayList<String> rdnAttrs = new ArrayList<String>();
		StringTokenizer toker = new StringTokenizer(rdnAttr,",",false);
		while (toker.hasMoreTokens()) {
			rdnAttrs.add(toker.nextToken());
		}
		
		String defaultOC = authParams.get("defaultOC").getValues().get(0);
		String dnLabel = authParams.get("dnLabel").getValues().get(0);
		
		
		
		
		as.setSuccess(true);
		
		try {
			LDAPSearchResults res = myvd.search(AuthUtil.getChainRoot(cfgMgr,act), 2, filter, new ArrayList<String>());

			if (res.hasMore()) {
				createUserFromDir(session, act, res);
			} else {
				createUnlinkedUser(session, act, rdnAttrs, dnLabel,
						defaultOC, subject);
			}
		} catch (LDAPException e) {
			if (e.getResultCode() == 32) {
				createUnlinkedUser(session, act, rdnAttrs, dnLabel,
						defaultOC, subject);
			} else {
				throw  new ServletException("Could not search for user",e);
			}
		}
		
		
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
		
		/*try {
			for (String oid : cert.getCriticalExtensionOIDs()) {
				byte[] derEncoded = cert.getExtensionValue(oid);
				
				//System.out.println("critical : " + oid);
			}
			
			for (String oid : cert.getNonCriticalExtensionOIDs()) {
				byte[] derEncoded = cert.getExtensionValue(oid);
				//System.out.println("noncritical : " + oid);
				ASN1InputStream ain = new ASN1InputStream(new ByteArrayInputStream(derEncoded));
				
				DEREncodable obj = ain.readObject();
				do {
					DEROctetString deros = (DEROctetString) obj;
					//System.out.println(deros.toString());
					X509Extension extension = new X509Extension(false,deros);
					//System.out.println(extension.toString());
					
					obj = ain.readObject();
				} while (obj != null);
				
			}
			
			
		} catch (Exception e) {
			throw new ServletException("Error parsing certificate",e);
		}*/

	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		
		this.crls = new ArrayList<CRLManager>();
		if (init.get("crl.names") != null) {
			for (String crlName : init.get("crl.names").getValues()) {
				if (crlName.isEmpty()) {
					break;
				}
				String type = init.get("crl." + crlName + ".type").getValues().get(0);
				try {
					CRLManager crl = (CRLManager) Class.forName(type).newInstance();
					crl.init(crlName, init, cfgMgr);
					this.crls.add(crl);
				} catch (Exception e) {
					logger.error("could not initialize crl : " + type,e);
				} 
			}
		
			StopableThread crlChecker = new CrlChecker(this.crls);
			Thread t = new Thread(crlChecker);
			
			this.cfgMgr.addThread(crlChecker);
			t.start();
			
		}
		
		this.extracts = new ArrayList<CertificateExtractSubjectAttribute>();
		if (init.get("extracts") != null) {
			Attribute attr = init.get("extracts");
			for (String className : attr.getValues()) {
				try {
					this.extracts.add((CertificateExtractSubjectAttribute) Class.forName(className).newInstance());
				} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
					logger.warn("Could not load : '" + className + "'",e);
				}
			}
		}
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		// TODO Auto-generated method stub
		return null;
	}

	private void createUserFromDir(HttpSession session, AuthChainType act,
			LDAPSearchResults res)
			throws LDAPException {
		LDAPEntry entry = res.next();
		while (res.hasMore()) res.next();
		
		Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
		AuthInfo authInfo = new AuthInfo(entry.getDN(),
				(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),
				act.getName(), act.getLevel(),(TremoloHttpSession) session);
		
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);

		

		while (it.hasNext()) {
			LDAPAttribute ldapAttr = it.next();
			Attribute attr = new Attribute(ldapAttr.getName());

			LinkedList<ByteArray> vals = ldapAttr.getAllValues();
			for (ByteArray ba : vals) {
				attr.getValues().add(new String(ba.getValue()));
			}
			authInfo.getAttribs().put(attr.getName(), attr);
		}

		
	}
	
	private void createUnlinkedUser(HttpSession session, AuthChainType act,
			ArrayList<String> rdnAttributes, String dnLabel, String defaultOC,
			HashMap<String,String> subject) {
		StringBuffer b = new StringBuffer();
		
		for (String attrName : rdnAttributes) {
			String rdnVal = subject.get(attrName);
			if (rdnVal != null) {
				b.append(attrName).append("=").append(rdnVal).append(",ou=").append(dnLabel).append(",ou=SSL,").append(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot());
				break;
			}
		}
		
		
		
		String dn = b.toString();
		AuthInfo authInfo = new AuthInfo(dn,
				(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),
				act.getName(), act.getLevel(),(TremoloHttpSession) session);
		
		((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);

		com.tremolosecurity.saml.Attribute attrib = new com.tremolosecurity.saml.Attribute(
				"objectClass", defaultOC);
		authInfo.getAttribs().put(attrib.getName(), attrib);

		for (String rdnAttr : subject.keySet()) {
			attrib = authInfo.getAttribs().get(rdnAttr);
			if (attrib == null) {
				attrib = new com.tremolosecurity.saml.Attribute(
						rdnAttr);
				authInfo.getAttribs().put(attrib.getName(), attrib);
			}
			
			attrib.getValues().add(subject.get(rdnAttr));
		}
		

		
	}
}

class CrlChecker implements StopableThread {
	boolean running = true;
	ArrayList<CRLManager> crls;
	
	
	public CrlChecker(ArrayList<CRLManager> crls) {
		this.crls = crls;
	}
	
	@Override
	public void run() {
		while (this.running) {
			CertAuth.logger.info("Checking CRLs");
			for (CRLManager crl : crls) {
				crl.validate();
			}
			
			try {
				//TODO
				//I hate threads
				synchronized (this) {
					this.wait(30000);
				}
				
			} catch (InterruptedException e) {
				this.running = false;
			}
		}
		
	}

	@Override
	public void stop() {
		this.running = false;
		
	}
	
}
