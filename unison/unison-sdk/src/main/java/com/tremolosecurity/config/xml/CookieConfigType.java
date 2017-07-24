/*******************************************************************************
 * Copyright 2015, 2017 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.07.23 at 10:28:21 AM EDT 
//


package com.tremolosecurity.config.xml;

import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Configuration for an application's cookies
 * 			
 * 
 * <p>Java class for cookieConfigType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="cookieConfigType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="sessionCookieName" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="domain" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="scope" type="{http://www.w3.org/2001/XMLSchema}integer"/>
 *         &lt;element name="logoutURI" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="keyAlias" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="keyPassword" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="secure" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="timeout" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "cookieConfigType", propOrder = {
    "sessionCookieName",
    "domain",
    "scope",
    "logoutURI",
    "keyAlias",
    "keyPassword",
    "secure",
    "timeout"
})
public class CookieConfigType {

    @XmlElement(required = true)
    protected String sessionCookieName;
    @XmlElement(required = true)
    protected String domain;
    @XmlElement(required = true)
    protected BigInteger scope;
    @XmlElement(required = true)
    protected String logoutURI;
    @XmlElement(required = true)
    protected String keyAlias;
    @XmlElement(required = true)
    protected String keyPassword;
    protected boolean secure;
    protected int timeout;

    /**
     * Gets the value of the sessionCookieName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSessionCookieName() {
        return sessionCookieName;
    }

    /**
     * Sets the value of the sessionCookieName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSessionCookieName(String value) {
        this.sessionCookieName = value;
    }

    /**
     * Gets the value of the domain property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Sets the value of the domain property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDomain(String value) {
        this.domain = value;
    }

    /**
     * Gets the value of the scope property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getScope() {
        return scope;
    }

    /**
     * Sets the value of the scope property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setScope(BigInteger value) {
        this.scope = value;
    }

    /**
     * Gets the value of the logoutURI property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLogoutURI() {
        return logoutURI;
    }

    /**
     * Sets the value of the logoutURI property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLogoutURI(String value) {
        this.logoutURI = value;
    }

    /**
     * Gets the value of the keyAlias property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyAlias() {
        return keyAlias;
    }

    /**
     * Sets the value of the keyAlias property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyAlias(String value) {
        this.keyAlias = value;
    }

    /**
     * Gets the value of the keyPassword property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyPassword() {
        return keyPassword;
    }

    /**
     * Sets the value of the keyPassword property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyPassword(String value) {
        this.keyPassword = value;
    }

    /**
     * Gets the value of the secure property.
     * 
     */
    public boolean isSecure() {
        return secure;
    }

    /**
     * Sets the value of the secure property.
     * 
     */
    public void setSecure(boolean value) {
        this.secure = value;
    }

    /**
     * Gets the value of the timeout property.
     * 
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * Sets the value of the timeout property.
     * 
     */
    public void setTimeout(int value) {
        this.timeout = value;
    }

}
