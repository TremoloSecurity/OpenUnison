<%@ page language="java" contentType="text/xml; charset=UTF-8"
    pageEncoding="UTF-8" import="java.net.*,com.tremolosecurity.util.*,com.tremolosecurity.server.*,com.tremolosecurity.config.util.*,com.tremolosecurity.config.xml.*,org.opensaml.core.config.*,java.security.*,org.apache.commons.codec.binary.*,org.opensaml.saml.saml2.metadata.impl.*,java.util.*,org.opensaml.saml.saml2.metadata.*,java.security.cert.*,org.opensaml.security.credential.*,org.opensaml.xmlsec.signature.impl.*,org.opensaml.xmlsec.signature.support.*,org.opensaml.xmlsec.signature.*,org.opensaml.xmlsec.signature.impl.*,java.security.cert.*,org.w3c.dom.Element"%><%

TremoloType tt = GlobalEntries.getGlobalEntries().getConfigManager().getCfg();
String idpName = request.getParameter("idp");
String excludens = request.getParameter("excludens");

URL url = new URL(request.getRequestURL().toString());
String baseURL = "https://" + url.getHost();
%><%= Saml2Metadata.generateIdPMetaData(baseURL,idpName,tt,GlobalEntries.getGlobalEntries().getConfigManager().getKeyStore(),excludens != null && excludens.equals("true") ) %>