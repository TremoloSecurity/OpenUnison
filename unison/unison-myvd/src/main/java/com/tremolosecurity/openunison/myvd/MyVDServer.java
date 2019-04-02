package com.tremolosecurity.openunison.myvd;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.Map;

import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.yaml.snakeyaml.Yaml;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;



public class MyVDServer {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MyVDServer.class.getName());
	static Gson gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();
	
	
	public static void main(String[] args) throws Exception {
		ListenerConfig config = null;
		logger.info("Starting MyVirtualDirectory " + net.sourceforge.myvd.server.Server.VERSION);
		if (args.length == 0) {
			logger.error("One argument required, path to yaml or json config");
			System.exit(1);
		} else if (args[0].endsWith(".yaml")) {
			logger.info("Parsing YAML : '" + args[0] + "'");
			Yaml yaml = new Yaml();
			Map<String,Object> map= (Map<String, Object>) yaml.load(new FileInputStream(args[0]));
			JSONObject jsonObject=new JSONObject(map);
			String json = jsonObject.toJSONString();
			config = gson.fromJson(json, ListenerConfig.class);
		} else {
			logger.info("Parsing JSON : '" + args[0] + "'");
			
			config = gson.fromJson(new InputStreamReader(new FileInputStream(args[0])), ListenerConfig.class);
		}
		
		final ListenerConfig fconfig = config;



		

		logger.info("Config Open Port : '" + config.getOpenPort() + "'");
		logger.info("Config Secure Port : '" + config.getSecurePort() + "'");
		logger.info("Config TLS Client Auth Mode : '" + config.getClientAuth() + "'");
		logger.info("Config TLS Allowed Client Subjects : '" + config.getAllowedClientNames() + "'");
		logger.info("Config TLS Protocols : '" + config.getAllowedTlsProtocols() + "'");
		logger.info("Config TLS Ciphers : '" + config.getCiphers() + "'");
		logger.info("Config Path to Deployment : '" + config.getPathToDeployment() + "'");
		logger.info("Config Path to Environment File : '" + config.getPathToEnvFile() + "'");
		logger.info("Support socket shutdown : " + config.isSocketShutdownListener());
		if (config.isSocketShutdownListener()) {
			logger.info("Socket shutdown host : '" + config.getSocketShutdownHost() + "'");
			logger.info("Socket shutdown port : '" + config.getSocketShutdownPort() + "'");
			logger.info("Socket shutdown command : '" + config.getSocketShutdownCommand() + "'");
		}

		
	}
	
}
