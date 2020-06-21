/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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

import java.util.HashSet;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.xnio.StreamConnection;

import io.undertow.server.HttpServerExchange;
import io.undertow.server.HttpUpgradeListener;
import io.undertow.servlet.websockets.ServletWebSocketHttpExchange;
import io.undertow.util.Headers;
import io.undertow.websockets.WebSocketConnectionCallback;
import io.undertow.websockets.WebSocketExtension;
import io.undertow.websockets.client.WebSocketClientNegotiation;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.protocol.Handshake;
import io.undertow.websockets.core.protocol.version07.Hybi07Handshake;
import io.undertow.websockets.core.protocol.version08.Hybi08Handshake;
import io.undertow.websockets.core.protocol.version13.Hybi13Handshake;

public class UnisonWebSocketClientNegotiation extends WebSocketClientNegotiation {


	boolean upgradeComplete;
	
	UndertowUpgradeRequestManager upgradeRequestManager;
	ServletWebSocketHttpExchange facade;
	Handshake handshaker;
	
	WebSocketConnectionCallback callback;
	
	public UnisonWebSocketClientNegotiation(List<String> supportedSubProtocols,
			List<WebSocketExtension> supportedExtensions) {
		super(supportedSubProtocols, supportedExtensions);
		this.upgradeComplete = false;
		
	}

	
	
	public UndertowUpgradeRequestManager getUpgradeRequestManager() {
		return upgradeRequestManager;
	}



	public void setUpgradeRequestManager(UndertowUpgradeRequestManager upgradeRequestManager) {
		this.upgradeRequestManager = upgradeRequestManager;
	}



	public ServletWebSocketHttpExchange getFacade() {
		return facade;
	}



	public void setFacade(ServletWebSocketHttpExchange facade) {
		this.facade = facade;
	}



	public Handshake getHandshaker() {
		return handshaker;
	}



	public void setHandshaker(Handshake handshaker) {
		this.handshaker = handshaker;
	}



	public WebSocketConnectionCallback getCallback() {
		return callback;
	}



	public void setCallback(WebSocketConnectionCallback callback) {
		this.callback = callback;
	}



	@Override
	public void handshakeComplete(String selectedProtocol, List<WebSocketExtension> selectedExtensions) {
		
		
		super.handshakeComplete(selectedProtocol, selectedExtensions);
		
		HashSet<String> subProtocols = new HashSet<String>();
        subProtocols.add(super.getSelectedSubProtocol());
        
        if (handshaker instanceof Hybi13Handshake) {
        	handshaker = new Hybi13Handshake(subProtocols,false);
        } else if (handshaker instanceof Hybi07Handshake) {
        	handshaker = new Hybi07Handshake(subProtocols,false);
        } else if (handshaker instanceof Hybi08Handshake) {
        	handshaker = new Hybi08Handshake(subProtocols,false);
        }
        
        final Handshake selected = handshaker;
        facade.upgradeChannel(new HttpUpgradeListener() {
            @Override
            public void handleUpgrade(StreamConnection streamConnection, HttpServerExchange exchange) {
                WebSocketChannel channel = selected.createChannel(facade, streamConnection, facade.getBufferPool());
                upgradeRequestManager.getPeerConnections().add(channel);
                callback.onConnect(facade, channel);
            }
        });
        handshaker.handshake(facade);
		this.upgradeComplete = true;
		
	}



	public boolean isUpgradeComplete() {
		return upgradeComplete;
	}
	
	

}
