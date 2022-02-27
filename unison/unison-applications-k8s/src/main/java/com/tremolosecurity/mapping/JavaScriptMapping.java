package com.tremolosecurity.mapping;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.CustomMapping;
import com.tremolosecurity.proxy.dynamicconfiguration.LoadJavaScriptMappingFromK8s;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class JavaScriptMapping implements CustomMapping {
	static Logger logger = Logger.getLogger(JavaScriptMapping.class);
	
	private static  Map<String,LoadJavaScriptMappingFromK8s> fromk8s;
	
	static {
		fromk8s = new HashMap<String,LoadJavaScriptMappingFromK8s>();
	}

	private String target;
	private String namespace;
	private String name;
	
	private String key;

	@Override
	public Attribute doMapping(User user, String attrname) {
		
		String jsmapping = null;
		LoadJavaScriptMappingFromK8s fromk8sns;
		synchronized (fromk8s) {
			fromk8sns = fromk8s.get(this.key);
			if (fromk8sns == null) {
				fromk8sns = new LoadJavaScriptMappingFromK8s();
				try {
					fromk8sns.loadJavaScriptMappings(GlobalEntries.getGlobalEntries().getConfigManager(), target,namespace);
				} catch (ProvisioningException e) {
					logger.warn("Could not create watch on " + target + "." + namespace,e);
					return new Attribute(attrname);
				}
				
				fromk8s.put(key, fromk8sns);
			}
			
		}
		
		String js = fromk8sns.getMapping(this.name);
		
		if (js == null) {
			logger.warn("JavaScriptMapping " + target + "." + namespace + "." + name + " does not exist");
			return new Attribute(attrname);
		}
		
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		try {
			Value initicalCtx = context.eval("js",js);
			Value doMapping = context.getBindings("js").getMember("doMapping");
			
			if (doMapping == null) {
				throw new ProvisioningException(target + "." + namespace + "." + name + " doMapping function does not exist");
			}
			
			if (!doMapping.canExecute()) {
				throw new ProvisioningException(target + "." + namespace + "." + name + " doMapping is not a function");
			}
			
			Value finishedMapping = doMapping.execute(user,attrname);
			
			return finishedMapping.as(Attribute.class);
			
			
		} catch (Throwable t) {
			logger.warn("Could not execute " + target + "." + namespace + "." + name,t);
			return new Attribute(attrname);
		} finally {
			context.close();
		}
		
		
	}

	@Override
	public void setParams(String... params) {
		this.target = params[0];
		this.namespace = params[1];
		this.name = params[2];
		this.key = this.target + "-" + this.namespace;
		
		

	}

}
