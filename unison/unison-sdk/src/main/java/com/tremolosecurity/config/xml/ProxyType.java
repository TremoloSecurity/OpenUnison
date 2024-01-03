/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
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
//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.2 
// See <a href="https://javaee.github.io/jaxb-v2/">https://javaee.github.io/jaxb-v2/</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2024.01.02 at 03:19:20 PM EST 
//


package com.tremolosecurity.config.xml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * custom proxy configuration for this URL
 * 
 * <p>Java class for proxyType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="proxyType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="connectionTimeoutMillis" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="requestTimeoutMillis" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="socketTimeoutMillis" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "proxyType", propOrder = {
    "connectionTimeoutMillis",
    "requestTimeoutMillis",
    "socketTimeoutMillis"
})
public class ProxyType {

    @XmlElement(defaultValue = "0")
    protected int connectionTimeoutMillis;
    @XmlElement(defaultValue = "0")
    protected int requestTimeoutMillis;
    @XmlElement(defaultValue = "0")
    protected int socketTimeoutMillis;

    /**
     * Gets the value of the connectionTimeoutMillis property.
     * 
     */
    public int getConnectionTimeoutMillis() {
        return connectionTimeoutMillis;
    }

    /**
     * Sets the value of the connectionTimeoutMillis property.
     * 
     */
    public void setConnectionTimeoutMillis(int value) {
        this.connectionTimeoutMillis = value;
    }

    /**
     * Gets the value of the requestTimeoutMillis property.
     * 
     */
    public int getRequestTimeoutMillis() {
        return requestTimeoutMillis;
    }

    /**
     * Sets the value of the requestTimeoutMillis property.
     * 
     */
    public void setRequestTimeoutMillis(int value) {
        this.requestTimeoutMillis = value;
    }

    /**
     * Gets the value of the socketTimeoutMillis property.
     * 
     */
    public int getSocketTimeoutMillis() {
        return socketTimeoutMillis;
    }

    /**
     * Sets the value of the socketTimeoutMillis property.
     * 
     */
    public void setSocketTimeoutMillis(int value) {
        this.socketTimeoutMillis = value;
    }

}
