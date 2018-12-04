/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.tremolosecurity.proxy.filter.HttpFilterRequest;

/**
 * Implementations will look to see if a GET is in fact an upgrade and manage the upgrade
 * @author mlb
 *
 */
public interface HttpUpgradeRequestManager {
	

	
	
	public void proxyWebSocket(HttpFilterRequest req,HttpServletResponse response,String url) throws Exception;

}
