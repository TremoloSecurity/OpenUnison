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

import org.apache.logging.log4j.Logger;

import io.undertow.websockets.core.AbstractReceiveListener;
import io.undertow.websockets.core.BufferedBinaryMessage;
import io.undertow.websockets.core.BufferedTextMessage;
import io.undertow.websockets.core.CloseMessage;
import io.undertow.websockets.core.StreamSourceFrameChannel;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSockets;

public class UnisonClientReceiveListener extends AbstractReceiveListener {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UnisonClientReceiveListener.class);
	
	WebSocketChannel client;
	
	public UnisonClientReceiveListener(WebSocketChannel client) {
		this.client = client;
	}

	@Override
	protected void onPing(final WebSocketChannel webSocketChannel, final StreamSourceFrameChannel channel) throws IOException {
		
		BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
		bbm.readBlocking(channel);
		WebSockets.sendPing(bbm.getData().getResource(), client, null);
	}

	@Override
	protected void onClose(WebSocketChannel webSocketChannel, StreamSourceFrameChannel channel) throws IOException {
		BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
		bbm.readBlocking(channel);
		WebSockets.sendClose(bbm.getData().getResource(), client, null);
	}

	@Override
	protected void onPong(WebSocketChannel webSocketChannel, StreamSourceFrameChannel messageChannel)
			throws IOException {
		BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
		bbm.readBlocking(messageChannel);
		WebSockets.sendPong(bbm.getData().getResource(), client, null);
	}

	@Override
	protected void onText(final WebSocketChannel webSocketChannel, final StreamSourceFrameChannel messageChannel)
			throws IOException {
		
		new Thread() {

			@Override
			public void run() {
				
				try {
					BufferedTextMessage btm = new BufferedTextMessage(true);
					btm.readBlocking(messageChannel);
					WebSockets.sendText(btm.getData(), client, null);
				} catch (IOException e) {
					onError(webSocketChannel,e);
				}
				
				
			}
			
		}.start();
		
		
	}

	@Override
	protected void onBinary(final WebSocketChannel webSocketChannel,final StreamSourceFrameChannel messageChannel)
			throws IOException {
		new Thread() {

			@Override
			public void run() {
				
				try {
					BufferedBinaryMessage bbm = new BufferedBinaryMessage(true);
					bbm.readBlocking(messageChannel);
					WebSockets.sendBinary(bbm.getData().getResource(), client, null);
				} catch (IOException e) {
					onError(webSocketChannel,e);
				}
				
				
			}
			
		}.start();
	}

	@Override
	protected void onError(WebSocketChannel channel, Throwable error) {
		logger.error("Channel Error",error);
	}

	@Override
	protected void onFullTextMessage(WebSocketChannel channel, BufferedTextMessage message) throws IOException {
		WebSockets.sendText(message.getData(), client, null);
	}

	@Override
	protected void onFullBinaryMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendBinary(message.getData().getResource(), client, null);
	}

	@Override
	protected void onFullPingMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendPing(message.getData().getResource(), client, null);
	}

	@Override
	protected void onFullPongMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendPong(message.getData().getResource(), client, null);
	}

	@Override
	protected void onFullCloseMessage(WebSocketChannel channel, BufferedBinaryMessage message) throws IOException {
		WebSockets.sendClose(message.getData().getResource(), client, null);
	}

	@Override
	protected void onCloseMessage(CloseMessage cm, WebSocketChannel channel) {
		WebSockets.sendClose(cm, client, null);
	}

	
	
}
