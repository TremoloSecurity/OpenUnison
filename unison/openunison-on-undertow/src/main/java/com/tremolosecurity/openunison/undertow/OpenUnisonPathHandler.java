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