/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.postProcess;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.tremolosecurity.proxy.ProxyRequest;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.HttpUpgradeListener;
import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.tremolosecurity.proxy.HttpUpgradeRequestManager;
import com.tremolosecurity.proxy.ProxyResponse;
import com.tremolosecurity.proxy.ProxySys;
import jakarta.servlet.http.HttpUpgradeHandler;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.RedirectHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecFactory;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.*;
import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.http.UriMethod;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.ssl.TremoloSSLSocketFactory;
import com.tremolosecurity.proxy.ssl.TremoloTrustManager;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.NVP;
import org.xnio.StreamConnection;
import org.xnio.streams.ChannelInputStream;
import org.xnio.streams.ChannelOutputStream;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class UriRequestProcess extends PostProcess {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UriRequestProcess.class);

	private static final ExecutorService EXEC = Executors.newCachedThreadPool();


	private Socket generateSocket(String url) throws IOException, NoSuchAlgorithmException, KeyManagementException {
		URL backendUrl = new URL(url);
		Socket backendSocket = null;
		if (backendUrl.getProtocol().equals("https")) {
			SSLContext sslContext = SSLContext.getInstance("TLS"); // or "TLSv1.2", "TLSv1.3"
			sslContext.init(GlobalEntries.getGlobalEntries().getConfigManager().getKeyManagerFactory().getKeyManagers(), GlobalEntries.getGlobalEntries().getConfigManager().getTrustManagerFactory().getTrustManagers(), null);
			SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

			int port = backendUrl.getPort();

			if (port <= 0) {
				port = 443;
			}

			SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(backendUrl.getHost(), port);

			return sslSocket;
		} else if (backendUrl.getProtocol().equals("http")) {
			int port = backendUrl.getPort();

			if (port <= 0) {
				port = 80;
			}

			backendSocket = new Socket(backendUrl.getHost(), port);
			backendSocket.setTcpNoDelay(true);

		}

		return backendSocket;
	}

	private static String generateWebSocketKey() {
		byte[] keyBytes = new byte[16];
		new SecureRandom().nextBytes(keyBytes);
		return Base64.getEncoder().encodeToString(keyBytes);
	}


	@Override
	public void postProcess(HttpFilterRequest req, HttpFilterResponse resp,
			UrlHolder holder,HttpFilterChain chain) throws Exception {
		
		
		String proxyTo = holder.getUrl().getProxyTo();
		
		HashMap<String,String> uriParams = (HashMap<String,String>) req.getAttribute("TREMOLO_URI_PARAMS");
		
		Iterator<String> names;
		StringBuffer proxyToURL = ProxyTools.getInstance().getGETUrl(req, holder, uriParams);
		
		boolean first = true;
		for (NVP p : req.getQueryStringParams()) {
			if (first) {
				proxyToURL.append('?');
				first = false;
			} else {
				proxyToURL.append('&');
			}
			
			proxyToURL.append(p.getName()).append('=').append(URLEncoder.encode(p.getValue(),"UTF-8"));
		}
		
		
		
		
		
		//com.tremolosecurity.proxy.HttpUpgradeRequestManager upgradeRequestManager = GlobalEntries.getGlobalEntries().getConfigManager().getUpgradeManager();
		
		if (req.getHeader("Connection") != null && req.getHeader("Connection").getValues().get(0).equalsIgnoreCase("Upgrade")) {

			HttpServerExchange exchange =
					ServletRequestContext.current().getOriginalRequest().getExchange();



			ProxyRequest proxyRequest = (ProxyRequest) req.getServletRequest();


			ProxyResponse pr = (ProxyResponse) resp.getServletResponse();
			StringBuffer wsUrl = new StringBuffer(proxyToURL.toString());
			if (wsUrl.toString().startsWith("https://")) {
				wsUrl.delete(0,7).insert(0,"wss://");
			} else {
				wsUrl.delete(0,6).insert(0,"ws://");
			}

			// generate a request
			final HttpRequestBase httpMethod = new UriMethod(req.getMethod(),"/chat");//this.getHttpMethod(proxyToURL.toString());
			req.setAttribute("TREMOLO_FINAL_URL", proxyToURL.toString());
			setHeadersCookies(req, holder, httpMethod,proxyToURL.toString());

			// generate response headers
			resp.addHeader("Sec-WebSocket-Accept",computeWebSocketAccept(req.getHeader("Sec-WebSocket-Key").getValues().get(0)));
			resp.addHeader("Upgrade", "websocket");


			// build a socket for the http connection
			final Socket backendSocket = generateSocket(proxyToURL.toString());

			InputStream backendIn = backendSocket.getInputStream();
			OutputStream backendOut = backendSocket.getOutputStream();

			// 2) Build WebSocket upgrade request to backend
			String wsKey = generateWebSocketKey();
			StringBuilder sb = new StringBuilder();

			String proxyurl = proxyToURL.toString();
			proxyurl = proxyurl.substring(proxyurl.indexOf("//") + 2);
			proxyurl = proxyurl.substring(proxyurl.indexOf('/'));

			// write the request to the socket
			sb.append("GET ").append(proxyurl).append(" HTTP/1.1\r\n");
			backendOut.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));

			for (Header header : httpMethod.getAllHeaders()) {
				if (!header.getName().equalsIgnoreCase("Sec-WebSocket-Key")) {
					sb.setLength(0);
					sb.append(header.getName()).append(": ").append(header.getValue()).append("\r\n");
					backendOut.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
				} else {
					sb.setLength(0);
					sb.append("Sec-WebSocket-Key: ").append(wsKey).append("\r\n");
					backendOut.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
				}

			}

			backendOut.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
			backendOut.flush();

			// 3) Read backend status line + headers
			BufferedReader br = new BufferedReader(
					new InputStreamReader(backendIn, StandardCharsets.ISO_8859_1)
			);

			String statusLine = br.readLine();
			if (statusLine == null || !statusLine.startsWith("HTTP/1.1 101")) {
				throw new IOException("Backend did not upgrade: " + statusLine);
			}

			String line;
			boolean upgradeOk = false;
			boolean connectionOk = false;
			boolean acceptOk = false;

			while ((line = br.readLine()) != null && !line.isEmpty()) {
				String lower = line.toLowerCase(Locale.ROOT);
				if (lower.startsWith("upgrade:") && lower.contains("websocket")) {
					upgradeOk = true;
				} else if (lower.startsWith("connection:") && lower.contains("upgrade")) {
					connectionOk = true;
				} else if (lower.startsWith("sec-websocket-accept:")) {
					// optionally verify the accept value against wsKey
					String keyFromServer = line.substring(line.indexOf(':') + 1).strip();
					acceptOk = keyFromServer.equalsIgnoreCase(computeWebSocketAccept(wsKey));
				} else {
					// response header should be added to the response
					String headerName = line.substring(0,line.indexOf(':')).strip();
					String headerValue = line.substring(line.indexOf(':') + 1).strip();
					resp.addHeader(headerName, headerValue);
				}
			}

			if (!upgradeOk || !connectionOk || !acceptOk) {
				throw new IOException("Backend WebSocket handshake invalid: " + statusLine);
			}

			exchange.upgradeChannel(new HttpUpgradeListener() {



				@Override
				public void handleUpgrade(StreamConnection clientConn, HttpServerExchange httpServerExchange) {
					try {





						// 4) At this point, backendIn / backendOut are at the start of WS frames.
						// Now we just tunnel bytes between client and backend.

						InputStream clientIn = new ChannelInputStream(clientConn.getSourceChannel());
						OutputStream clientOut = new ChannelOutputStream(clientConn.getSinkChannel());

						EXEC.execute(() -> pump(clientIn, backendOut, clientConn, backendSocket));
						EXEC.execute(() -> pump(backendIn, clientOut, clientConn, backendSocket));


					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				}



				private static void pump(InputStream in, OutputStream out,
										 StreamConnection clientConn, Socket backendSocket) {
					byte[] buf = new byte[8192];
					try {
						int r;
						while ((r = in.read(buf)) != -1) {
							out.write(buf, 0, r);
							out.flush();
						}
					} catch (Exception ignored) {
					} finally {
						// When one direction closes, tear down both sides
						try {
							clientConn.close();
						} catch (Exception ignore) {
						}
						try {
							backendSocket.close();
						} catch (Exception ignore) {
						}
					}
				}
			});




			
		} else {
			CloseableHttpClient httpclient = this.getHttp(proxyTo, req.getServletRequest(), holder);
			
			//HttpGet httpget = new HttpGet(proxyToURL.toString());
			
			HttpRequestBase httpMethod = new UriMethod(req.getMethod(),proxyToURL.toString());//this.getHttpMethod(proxyToURL.toString());
			
			req.setAttribute("TREMOLO_FINAL_URL", proxyToURL.toString());
			
			setHeadersCookies(req, holder, httpMethod,proxyToURL.toString());

			HttpContext ctx = (HttpContext) req.getSession().getAttribute(ProxySys.HTTP_CTX);
			HttpResponse response = httpclient.execute(httpMethod,ctx);
			
			postProcess(req, resp, holder, response,proxyToURL.toString(),chain,httpMethod);
			
		}
		
		
		
		
		
		
		

	}

	private static String computeWebSocketAccept(String key) throws Exception {
		String magic = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] digest = sha1.digest(magic.getBytes(StandardCharsets.ISO_8859_1));
		return Base64.getEncoder().encodeToString(digest);
	}

	

	@Override
	public boolean addHeader(String name) {
		return true;
	}

}
