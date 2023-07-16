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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;
import org.xnio.IoFuture;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.Xnio;
import org.xnio.XnioWorker;


import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

import io.undertow.Undertow;
import io.undertow.connector.ByteBufferPool;
import io.undertow.connector.PooledByteBuffer;
import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.websockets.client.WebSocketClient;
import io.undertow.websockets.client.WebSocketClientNegotiation;
import io.undertow.websockets.core.AbstractReceiveListener;
import io.undertow.websockets.core.BufferedBinaryMessage;
import io.undertow.websockets.core.BufferedTextMessage;
import io.undertow.websockets.core.CloseMessage;
import io.undertow.websockets.core.StreamSinkFrameChannel;
import io.undertow.websockets.core.StreamSourceFrameChannel;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSocketFrameType;
import io.undertow.websockets.core.WebSockets;
import io.undertow.websockets.spi.WebSocketHttpExchange;

public class UnisonReceiveListener extends AbstractReceiveListener {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UnisonReceiveListener.class);
	
	URI uri;
	XnioWorker worker;
	ByteBufferPool pool;
	private WebSocketChannel wsClient;
	private CountDownLatch latch;
	private AtomicReference<String> result;

	private ConnectionBuilder connectionBuilder;

	
	
	public static Charset charset = Charset.forName("UTF-8");
	public static CharsetDecoder decoder = charset.newDecoder();
	
	
	
	static Set<String> ignoreHeaders;
	
	static {
		ignoreHeaders = new HashSet<String>();
		ignoreHeaders.add("Sec-WebSocket-Key");
		ignoreHeaders.add("Sec-WebSocket-Version");
		ignoreHeaders.add("Upgrade");
		ignoreHeaders.add("Connection");
		ignoreHeaders.add("Upgrade");
	}
	
	public UnisonReceiveListener(String url,HttpFilterRequest request,HttpServletResponse resp,UnisonWebSocketClientNegotiation clientNegotiation) throws URISyntaxException, IllegalArgumentException, IOException {
		this.uri = new URI( new StringBuilder().append(  ( url.startsWith("https") ? "wss" : "ws")).append(url.substring(url.indexOf(':'))).toString());
		
		
		
		
		Xnio xnio = Xnio.getInstance();
		
		UndertowXnioSsl ssl = new UndertowXnioSsl(xnio, OptionMap.EMPTY, GlobalEntries.getGlobalEntries().getConfigManager().getSSLContext());
		
		pool = new DefaultByteBufferPool(true,1024);
		worker = xnio.createWorker(OptionMap.builder()
                .set(Options.WORKER_IO_THREADS, 2)
                .set(Options.CONNECTION_HIGH_WATER, 1000000)
                .set(Options.CONNECTION_LOW_WATER, 1000000)
                .set(Options.WORKER_TASK_CORE_THREADS, 30)
                .set(Options.WORKER_TASK_MAX_THREADS, 30)
                .set(Options.TCP_NODELAY, true)
                .set(Options.CORK, true)
                .getMap());
		
		//UndertowXnioSsl ssl = new UndertowXnioSsl(Xnio.getInstance(), OptionMap.EMPTY, DefaultServer.getClientSSLContext());
        this.connectionBuilder = ConnectionBuilder.connectionBuilder(worker,pool , this.uri);
        
        
        connectionBuilder.setClientNegotiation(clientNegotiation);
        
        connectionBuilder.setSsl(ssl);
        
        
        
        Iterator<String> headerNames =  request.getHeaderNames();
        
        while (headerNames.hasNext()) {
        	String headerName = headerNames.next();
        	if (! ignoreHeaders.contains(headerName)) {
        		ArrayList<String> vals = new ArrayList<String>();
        		Attribute headerAttr = request.getHeader(headerName);
        		vals.addAll(headerAttr.getValues());
        		
        		connectionBuilder.getAdditionalHeaders().put(headerName, vals);
        		
        	}
        	
        }
        
        
        
        
	}
	
	public void initializeFromCallback(WebSocketHttpExchange exchange, WebSocketChannel channel) throws CancellationException, IOException {
		
        
        this.wsClient.getReceiveSetter().set(new UnisonClientReceiveListener(channel));
        this.wsClient.resumeReceives();
        latch = new CountDownLatch(1);
        result = new AtomicReference<>();
	}

	public void startConnection() throws IOException {
		IoFuture<WebSocketChannel> future = connectionBuilder.connect();
        future.await(4, TimeUnit.SECONDS);
        wsClient = future.get();
	}

	@Override
	protected void onPing(WebSocketChannel webSocketChannel, StreamSourceFrameChannel channel) throws IOException {
		
		BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
		bbm.readBlocking(channel);
		WebSockets.sendPing(bbm.getData().getResource(), wsClient, null);
		
		
		
	}

	@Override
	protected void onClose(WebSocketChannel webSocketChannel, StreamSourceFrameChannel channel) throws IOException {
		BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
		bbm.readBlocking(channel);
		WebSockets.sendClose(bbm.getData().getResource(), wsClient, null);
	}

	@Override
	protected void onPong(WebSocketChannel webSocketChannel, StreamSourceFrameChannel messageChannel)
			throws IOException {
		BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
		bbm.readBlocking(messageChannel);
		WebSockets.sendPong(bbm.getData().getResource(), wsClient, null);
	}



	
	@Override
	protected void onText(WebSocketChannel webSocketChannel, StreamSourceFrameChannel messageChannel)
			throws IOException {
		BufferedTextMessage btm = new BufferedTextMessage(true);
		btm.readBlocking(messageChannel);
		
		WebSockets.sendText(btm.getData(), wsClient, null);
		
	}

	@Override
	protected void onBinary(WebSocketChannel webSocketChannel, StreamSourceFrameChannel messageChannel)
			throws IOException {
		BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
		bbm.readBlocking(messageChannel);
		WebSockets.sendBinary(bbm.getData().getResource(), wsClient, null);
	}

	@Override
	protected void onError(WebSocketChannel channel, Throwable error) {
		logger.error("Channel Error",error);
	}

	@Override
	protected void onFullTextMessage(WebSocketChannel channel, BufferedTextMessage message) throws IOException {
		WebSockets.sendText(message.getData(), wsClient, null);
	}

	@Override
	protected void onFullBinaryMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendBinary(message.getData().getResource(), wsClient, null);
	}

	@Override
	protected void onFullPingMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendPing(message.getData().getResource(), wsClient, null);
	}

	@Override
	protected void onFullPongMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendPong(message.getData().getResource(), wsClient, null);
	}

	@Override
	protected void onFullCloseMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendClose(message.getData().getResource(), wsClient, null);
	}

	@Override
	protected void onCloseMessage(CloseMessage cm, WebSocketChannel channel) {
		WebSockets.sendClose(cm, wsClient, null);
		
	}



	
}
