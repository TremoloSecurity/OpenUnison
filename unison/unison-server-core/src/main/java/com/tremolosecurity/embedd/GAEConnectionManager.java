/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.embedd;

/*
 ESXX - The friendly ECMAscript/XML Application MyVDServerImpl
 Copyright (C) 2007-2010 Martin Blom <martin@blom.org>

 This program is free software: you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public License
 as published by the Free Software Foundation, either version 3
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.


 PLEASE NOTE THAT THIS FILE'S LICENSE IS DIFFERENT FROM THE REST OF ESXX!
 */

import java.net.*;
import java.util.concurrent.TimeUnit;
import org.apache.http.conn.*;
import org.apache.http.params.*;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.scheme.*;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UnisonConfigManagerImpl;

public class GAEConnectionManager implements ClientConnectionManager {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(GAEConnectionManager.class);
	
	public GAEConnectionManager() {
		SocketFactory no_socket_factory = new SocketFactory() {
			public Socket connectSocket(Socket sock, String host, int port,
					InetAddress localAddress, int localPort, HttpParams params) {
				return null;
			}

			public Socket createSocket() {
				return null;
			}

			public boolean isSecure(Socket s) {
				return false;
			}
		};

		schemeRegistry = new SchemeRegistry();
		schemeRegistry.register(new Scheme("http", no_socket_factory, 80));
		schemeRegistry.register(new Scheme("https", no_socket_factory, 443));
	}

	@Override
	public SchemeRegistry getSchemeRegistry() {
		return schemeRegistry;
	}

	@Override
	public ClientConnectionRequest requestConnection(final HttpRoute route,
			final Object state) {
		return new ClientConnectionRequest() {
			public void abortRequest() {
				// Nothing to do
			}

			public ManagedClientConnection getConnection(long timeout,
					TimeUnit tunit) {
				return GAEConnectionManager.this.getConnection(route, state);
			}
		};
	}

	@Override
	public void releaseConnection(ManagedClientConnection conn,
			long validDuration, TimeUnit timeUnit) {
	}

	@Override
	public void closeIdleConnections(long idletime, TimeUnit tunit) {
	}

	@Override
	public void closeExpiredConnections() {
	}

	@Override
	public void shutdown() {
	}

	private ManagedClientConnection getConnection(HttpRoute route, Object state) {
		return null;//new GAEClientConnection(this, route, state);
	}

	private SchemeRegistry schemeRegistry;
}
