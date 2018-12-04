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
package com.tremolosecurity.openunison.undertow;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.PathHandler;

/**
 * OpenUnisonPathHandler
 */
public class OpenUnisonPathHandler implements HttpHandler {
    private PathHandler pathHandler;

    public OpenUnisonPathHandler(PathHandler pathHandler) {
        this.pathHandler = pathHandler;
    }

	@Override
	public void handleRequest(HttpServerExchange exchange) throws Exception {
        exchange.setRequestURI(exchange.getRequestURI().toLowerCase());
        exchange.setRequestPath(exchange.getRequestPath().toLowerCase());
        exchange.setRelativePath(exchange.getRelativePath().toLowerCase());
        
		pathHandler.handleRequest(exchange);
	}

    
}