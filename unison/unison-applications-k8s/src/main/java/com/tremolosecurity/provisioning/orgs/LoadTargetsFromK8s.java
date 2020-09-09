package com.tremolosecurity.provisioning.orgs;

import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.OrgType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.TargetAttributeType;
import com.tremolosecurity.config.xml.TargetConfigType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.k8s.watch.K8sWatchTarget;
import com.tremolosecurity.k8s.watch.K8sWatcher;
import com.tremolosecurity.openunison.util.config.OpenUnisonConfigLoader;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.targets.DynamicTargets;
import com.tremolosecurity.saml.Attribute;

public class LoadTargetsFromK8s implements DynamicTargets, K8sWatchTarget {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadTargetsFromK8s.class.getName());
	
	K8sWatcher k8sWatch;
	
	TremoloType tremolo;

	private ProvisioningEngine provisioningEngine;
	private ConfigManager cfgMgr;

	@Override
	public void addObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		JSONObject metadata = (JSONObject) item.get("metadata");
		String name = (String) metadata.get("name");
		TargetType target = new TargetType();
		target.setName(name);
		target.setParams(new TargetConfigType());
		
		try {
			target.setClassName(OpenUnisonConfigLoader.generateOpenUnisonConfig(  (String)item.get("className")));
			JSONArray params = (JSONArray) item.get("params");
			for (Object o : params) {
				JSONObject param = (JSONObject) o;
				ParamType pt = new ParamType();
				pt.setName(OpenUnisonConfigLoader.generateOpenUnisonConfig((String) param.get("name")  ));
				pt.setValue(OpenUnisonConfigLoader.generateOpenUnisonConfig((String) param.get("value")  ));
				target.getParams().getParam().add(pt);
			}
			
			JSONArray attrs = (JSONArray) item.get("targetAttributes");
			for (Object o : attrs) {
				JSONObject attr = (JSONObject) o;
				TargetAttributeType ta = new TargetAttributeType();
				ta.setName(OpenUnisonConfigLoader.generateOpenUnisonConfig((String) attr.get("name")));
				ta.setSource(OpenUnisonConfigLoader.generateOpenUnisonConfig((String) attr.get("source")));
				ta.setSourceType((String) attr.get("sourceType"));
				ta.setTargetType((String) attr.get("targetType"));
				target.getTargetAttribute().add(ta);
			}
			
			this.provisioningEngine.addTarget(cfgMgr, target);
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not add target '" + name + "'",e);
		} 
		
		
	}

	@Override
	public void modifyObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void deleteObject(TremoloType cfg, JSONObject item) throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	@Override
	public void loadDynamicTargets(ConfigManager cfgMgr, ProvisioningEngine provisioningEngine,
			Map<String, Attribute> init) throws ProvisioningException {
		this.tremolo = cfgMgr.getCfg();
		String k8sTarget = 	init.get("k8starget").getValues().get(0);
		String namespace = init.get("namespace").getValues().get(0);
		String uri = "/apis/openunison.tremolo.io/v1/namespaces/" + namespace + "/targets";
		
		
		this.provisioningEngine = provisioningEngine;
		this.cfgMgr = cfgMgr;
		
		this.k8sWatch = new K8sWatcher(k8sTarget,namespace,uri,this,cfgMgr,provisioningEngine);
		
		this.k8sWatch.initalRun();

	}

}
