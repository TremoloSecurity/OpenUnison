package com.tremolosecurity.proxy.filters.custom;

import org.apache.log4j.Logger;

import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

public class CreateAWSRoleAttribute implements HttpFilter {

	static Logger logger = Logger.getLogger(CreateAWSRoleAttribute.class.getName());
	
	String sourceAttribute;
	String accountNumber;
	String idpName;
	
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		Attribute source = userData.getAttribs().get(this.sourceAttribute);
		if (source == null) {
			logger.warn("Source attribute not found");
		} else {
			StringBuffer role = new StringBuffer();
			Attribute roles = new Attribute("https://aws.amazon.com/SAML/Attributes/Role");
			for (String groupName : source.getValues()) {
				role.setLength(0);
				role.append("arn:aws:iam::")
					.append(this.accountNumber)
					.append(":role/")
					.append(groupName)
					.append(",arn:aws:iam::")
					.append(this.accountNumber)
					.append(":saml-provider/")
					.append(this.idpName);
				roles.getValues().add(role.toString());
			}
			
			userData.getAttribs().put(roles.getName(), roles);
			
			chain.nextFilter(request, response, chain);
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.sourceAttribute = this.getAttribute("sourceAttribute", config);
		this.idpName = this.getAttribute("idpName", config);
		this.accountNumber = this.getAttribute("accountNumber", config);

	}
	
	private String getAttribute(String name,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(name + " not configured");
		}
		
		logger.info(name + " - '" + attr.getValues().get(0) + "'");
		
		return attr.getValues().get(0);
		
	}

}
