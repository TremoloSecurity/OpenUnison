package com.tremolosecurity.proxy.util;

/*
 * Copyright 2005-2017 Red Hat, Inc.
 * Red Hat licenses this file to you under the Apache License, version
 * 2.0 (the "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */


import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * @author <a href="mailto:ovidiu@feodorov.com">Ovidiu Feodorov</a>
 * @author <a href="mailto:tim.fox@jboss.com">Tim Fox</a>
 */
public final class XMLUtil {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(XMLUtil.class);
	
    private XMLUtil() {
        // Utility class
    }

    public static Element stringToElement(final String s) throws Exception {
        return XMLUtil.readerToElement(new StringReader(s));
    }

    public static Element urlToElement(final URL url) throws Exception {
        return XMLUtil.readerToElement(new InputStreamReader(url
                .openStream()));
    }

    public static String readerToString(final Reader r) throws Exception {
        // Read into string
        StringBuilder buff = new StringBuilder();
        int c;
        while ((c = r.read()) != -1) {
            buff.append((char) c);
        }
        return buff.toString();
    }

    public static Element readerToElement(final Reader r) throws Exception {
        // Read into string
        StringBuffer buff = new StringBuffer();
        int c;
        while ((c = r.read()) != -1) {
            buff.append((char) c);
        }

        // Quick hardcoded replace, FIXME this is a kludge - use regexp to match properly
        String s = buff.toString();

        StringReader sreader = new StringReader(s);

        DocumentBuilderFactory factory = DocumentBuilderFactory
                .newInstance();
        // see http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6529766
        factory.setNamespaceAware(true);
        DocumentBuilder parser = factory.newDocumentBuilder();
        Document doc = parser.parse(new InputSource(sreader));
        return doc.getDocumentElement();
    }

    public static String elementToString(final Node n) {

        String name = n.getNodeName();

        short type = n.getNodeType();

        if (Node.CDATA_SECTION_NODE == type) {
            return "<![CDATA[" + n.getNodeValue() + "]]>";
        }

        if (name.startsWith("#")) {
            return "";
        }

        StringBuffer sb = new StringBuffer();
        sb.append('<').append(name);

        NamedNodeMap attrs = n.getAttributes();
        if (attrs != null) {
            for (int i = 0; i < attrs.getLength(); i++) {
                Node attr = attrs.item(i);
                sb.append(' ').append(attr.getNodeName()).append("=\"")
                        .append(attr.getNodeValue()).append("\"");
            }
        }

        String textContent = null;
        NodeList children = n.getChildNodes();

        if (children.getLength() == 0) {
            if ((textContent = XMLUtil.getTextContent(n)) != null
                    && !"".equals(textContent)) {
                sb.append(textContent).append("</").append(name)
                        .append('>');
            } else {
                sb.append("/>").append('\n');
            }
        } else {
            sb.append('>').append('\n');
            boolean hasValidChildren = false;
            for (int i = 0; i < children.getLength(); i++) {
                String childToString = XMLUtil.elementToString(children
                        .item(i));
                if (!"".equals(childToString)) {
                    sb.append(childToString);
                    hasValidChildren = true;
                }
            }

            if (!hasValidChildren
                    && (textContent = XMLUtil.getTextContent(n)) != null) {
                sb.append(textContent);
            }

            sb.append("</").append(name).append('>');
        }

        return sb.toString();
    }

    private static final Object[] EMPTY_ARRAY = new Object[0];

    /**
     * This metod is here because Node.getTextContent() is not available in JDK 1.4 and I would like
     * to have an uniform access to this functionality.
     * <p>
     * Note: if the content is another element or set of elements, it returns a string representation
     * of the hierarchy.
     * <p>
     * TODO implementation of this method is a hack. Implement it properly.
     */
    public static String getTextContent(final Node n) {
        if (n.hasChildNodes()) {
            StringBuffer sb = new StringBuffer();
            NodeList nl = n.getChildNodes();
            for (int i = 0; i < nl.getLength(); i++) {
                sb.append(XMLUtil.elementToString(nl.item(i)));
                if (i < nl.getLength() - 1) {
                    sb.append('\n');
                }
            }

            String s = sb.toString();
            if (s.length() != 0) {
                return s;
            }
        }

        Method[] methods = Node.class.getMethods();

        for (Method getTextContext : methods) {
            if ("getTextContent".equals(getTextContext.getName())) {
                try {
                    return (String) getTextContext.invoke(n,
                            XMLUtil.EMPTY_ARRAY);
                } catch (Exception e) {
                    logger.error(e);
                    return null;
                }
            }
        }

        String textContent = null;

        if (n.hasChildNodes()) {
            NodeList nl = n.getChildNodes();
            for (int i = 0; i < nl.getLength(); i++) {
                Node c = nl.item(i);
                if (c.getNodeType() == Node.TEXT_NODE) {
                    textContent = n.getNodeValue();
                    if (textContent == null) {
                        // TODO This is a hack. Get rid of it and implement this properly
                        String s = c.toString();
                        int idx = s.indexOf("#text:");
                        if (idx != -1) {
                            textContent = s.substring(idx + 6).trim();
                            if (textContent.endsWith("]")) {
                                textContent = textContent.substring(0,
                                        textContent.length() - 1);
                            }
                        }
                    }
                    if (textContent == null) {
                        break;
                    }
                }
            }

            // TODO This is a hack. Get rid of it and implement this properly
            String s = n.toString();
            int i = s.indexOf('>');
            int i2 = s.indexOf("</");
            if (i != -1 && i2 != -1) {
                textContent = s.substring(i + 1, i2);
            }
        }

        return textContent;
    }

   

    // Inner classes --------------------------------------------------------------------------------

}