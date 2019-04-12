/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.sdk;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.util.NVP;

public interface SourceList {
	public void init(ScaleAttribute attribute,Map<String,Attribute> config);
	
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception;
	
	public String validate(String value,HttpFilterRequest request) throws Exception;

}
