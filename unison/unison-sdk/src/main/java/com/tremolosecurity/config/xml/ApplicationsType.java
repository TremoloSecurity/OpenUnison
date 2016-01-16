/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.12.27 at 08:58:13 PM EST 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * List of all applications configured on this Unison instance
 * 
 * <p>Java class for applicationsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="applicationsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="application" type="{http://www.tremolosecurity.com/tremoloConfig}applicationType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="openSessionCookieName" type="{http://www.w3.org/2001/XMLSchema}string" default="unisonOpenSession" />
 *       &lt;attribute name="openSessionTimeout" type="{http://www.w3.org/2001/XMLSchema}int" default="900" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "applicationsType", propOrder = {
    "application"
})
public class ApplicationsType {

    protected List<ApplicationType> application;
    @XmlAttribute(name = "openSessionCookieName")
    protected String openSessionCookieName;
    @XmlAttribute(name = "openSessionTimeout")
    protected Integer openSessionTimeout;

    /**
     * Gets the value of the application property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the application property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getApplication().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ApplicationType }
     * 
     * 
     */
    public List<ApplicationType> getApplication() {
        if (application == null) {
            application = new ArrayList<ApplicationType>();
        }
        return this.application;
    }

    /**
     * Gets the value of the openSessionCookieName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOpenSessionCookieName() {
        if (openSessionCookieName == null) {
            return "unisonOpenSession";
        } else {
            return openSessionCookieName;
        }
    }

    /**
     * Sets the value of the openSessionCookieName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOpenSessionCookieName(String value) {
        this.openSessionCookieName = value;
    }

    /**
     * Gets the value of the openSessionTimeout property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public int getOpenSessionTimeout() {
        if (openSessionTimeout == null) {
            return  900;
        } else {
            return openSessionTimeout;
        }
    }

    /**
     * Sets the value of the openSessionTimeout property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setOpenSessionTimeout(Integer value) {
        this.openSessionTimeout = value;
    }

}
