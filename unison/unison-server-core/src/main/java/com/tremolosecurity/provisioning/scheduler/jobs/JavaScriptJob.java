/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.scheduler.jobs;

import com.tremolosecurity.proxy.mappings.JavaScriptMappings;
import com.tremolosecurity.server.GlobalEntries;
import org.apache.log4j.Logger;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;
import org.quartz.JobExecutionContext;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

public class JavaScriptJob extends UnisonJob {
	static Logger logger = Logger.getLogger(JavaScriptJob.class.getName());

	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {
		Context jsContext = Context.newBuilder("js").allowAllAccess(true).build();

		List<String> jsToLoad = new ArrayList<String>();

		String includeJsList = context.getJobDetail().getJobDataMap().getString("includeJs");
		if (includeJsList != null) {
			StringTokenizer st = new StringTokenizer(includeJsList, ",");
			st.asIterator().forEachRemaining(includeJs -> jsToLoad.add((String) includeJs));
		}

		if (jsToLoad.size() > 0) {
			JavaScriptMappings javascripts = (JavaScriptMappings) GlobalEntries.getGlobalEntries().get("javascripts");
			if (javascripts != null) {
				for (String jsName : jsToLoad) {
					String javascript = javascripts.getMapping(jsName);
					if (javascript != null) {
						jsContext.eval("js", javascript);
					} else {
						logger.warn("JavScript " + jsName + " not found");
					}
				}
			} else {
				logger.warn("No javascripts loader initialized");
			}
		}

		
		String jsScript = context.getJobDetail().getJobDataMap().getString("javaScript");
		Value val = jsContext.eval("js",jsScript);
		
		Value execute = jsContext.getBindings("js").getMember("execute");
		if (execute == null || ! execute.canExecute()) {
			throw new ProvisioningException("No execute method in javascript");
		}
		
		execute.executeVoid(configManager,context);
		jsContext.close();

	}

}
