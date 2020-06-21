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
package com.tremolosecurity.proxy.undertow;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.xnio.StreamConnection;

import com.tremolosecurity.proxy.HttpUpgradeRequestManager;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;

import io.undertow.UndertowLogger;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.HttpUpgradeListener;
import io.undertow.servlet.websockets.ServletWebSocketHttpExchange;
import io.undertow.util.StatusCodes;
import io.undertow.websockets.WebSocketConnectionCallback;
import io.undertow.websockets.client.WebSocketClientNegotiation;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.protocol.Handshake;
import io.undertow.websockets.core.protocol.version07.Hybi07Handshake;
import io.undertow.websockets.core.protocol.version08.Hybi08Handshake;
import io.undertow.websockets.core.protocol.version13.Hybi13Handshake;
import io.undertow.websockets.spi.WebSocketHttpExchange;



public class UndertowUpgradeRequestManager implements HttpUpgradeRequestManager {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(UndertowUpgradeRequestManager.class.getName());
	
	public static final String SESSION_HANDLER = "io.undertow.handler";

    private final List<Handshake> handshakes;

    

    private Set<WebSocketChannel> peerConnections;
    
    public UndertowUpgradeRequestManager() {
    	this.handshakes = handshakes();
    	
    	peerConnections = Collections.newSetFromMap(new ConcurrentHashMap<WebSocketChannel, Boolean>());
    }
	

    

	public Set<WebSocketChannel> getPeerConnections() {
		return peerConnections;
	}




	@Override
	public void proxyWebSocket(final HttpFilterRequest req, HttpServletResponse resp,final String url) throws Exception {
		final ServletWebSocketHttpExchange facade = new ServletWebSocketHttpExchange(req.getServletRequest(), resp, peerConnections);
        Handshake handshaker = null;
        for (Handshake method : handshakes) {
            if (method.matches(facade)) {
                handshaker = method;
                break;
            }
        }

        if (handshaker == null) {
            UndertowLogger.REQUEST_LOGGER.debug("Could not find hand shaker for web socket request");
            resp.sendError(StatusCodes.BAD_REQUEST);
            return;
        }
        
        ArrayList<String> protocols = new ArrayList<String>();
        Attribute subProtocols = req.getHeader("Sec-WebSocket-Protocol");
        if (subProtocols != null) {
        	StringTokenizer protToker = new StringTokenizer(subProtocols.getValues().get(0),",",false);
        	
        	while (protToker.hasMoreTokens()) {
        		protocols.add(protToker.nextToken().trim());
        	}
        	
        	
        	
        	
        }
        
        UnisonWebSocketClientNegotiation clientNegotionation = new UnisonWebSocketClientNegotiation(protocols,new ArrayList<io.undertow.websockets.WebSocketExtension>());
        
        
        
        
        
        final UnisonReceiveListener unisonReceiveListener = new UnisonReceiveListener(url,req,resp,clientNegotionation);
        
        clientNegotionation.setFacade(facade);
        clientNegotionation.setHandshaker(handshaker);
        clientNegotionation.setUpgradeRequestManager(this);
        
        final WebSocketConnectionCallback callback = new WebSocketConnectionCallback() {
            @Override
            public void onConnect(final WebSocketHttpExchange exchange, final WebSocketChannel channel) {
                
            	try {
            		unisonReceiveListener.initializeFromCallback(exchange, channel);
  					channel.getReceiveSetter().set(unisonReceiveListener);
  				} catch (IllegalArgumentException | IOException e) {
  					logger.error("Could not initiate websocket",e);
  					
  				} 
  				
  				
  				
  				channel.resumeReceives();
  				
  				
            }
        };
        
        clientNegotionation.setCallback(callback);
        
        unisonReceiveListener.startConnection();
        
        int count = 0;
        while (! clientNegotionation.isUpgradeComplete()) {
        	Thread.sleep(100);
        	if (++count == 20) {
        		throw new Exception("websocket proxy timeout");
        	}
        }
		
	}



	/*private void upgradeClientConnection(final ServletWebSocketHttpExchange facade, Handshake handshaker,
			final UnisonReceiveListener unisonReceiveListener, final WebSocketConnectionCallback callback) {
		HashSet<String> subProtocols = new HashSet<String>();
        subProtocols.add(unisonReceiveListener.getClientNegotionation().getSelectedSubProtocol());
        
        if (handshaker instanceof Hybi13Handshake) {
        	handshaker = new Hybi13Handshake(subProtocols,false);
        } else if (handshaker instanceof Hybi07Handshake) {
        	handshaker = new Hybi07Handshake(subProtocols,false);
        } else if (handshaker instanceof Hybi08Handshake) {
        	handshaker = new Hybi08Handshake(subProtocols,false);
        }
        
        final Handshake selected = handshaker;
        
        handshaker.handshake(facade);
	}*/
	
	protected List<Handshake> handshakes() {
        List<Handshake> handshakes = new ArrayList<>();
        handshakes.add(new Hybi13Handshake());
        handshakes.add(new Hybi08Handshake());
        handshakes.add(new Hybi07Handshake());
        return handshakes;
    }

}
