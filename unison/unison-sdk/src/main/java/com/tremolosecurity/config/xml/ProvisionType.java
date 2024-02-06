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
// This file was generated by the Eclipse Implementation of JAXB, v3.0.0 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2024.02.03 at 03:46:44 PM EST 
//


package com.tremolosecurity.config.xml;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlType;


/**
 * 
 * 				Workflow task for provisioning an account to a target
 * 				type, may not have children
 * 			
 * 
 * <p>Java class for provisionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="provisionType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://www.tremolosecurity.com/tremoloConfig}workflowTaskType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="attributes" type="{http://www.tremolosecurity.com/tremoloConfig}listType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="sync" type="{http://www.w3.org/2001/XMLSchema}boolean" /&gt;
 *       &lt;attribute name="target" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="setPassword" type="{http://www.w3.org/2001/XMLSchema}boolean" default="false" /&gt;
 *       &lt;attribute name="onlyPassedInAttributes" type="{http://www.w3.org/2001/XMLSchema}boolean" default="false" /&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "provisionType", propOrder = {
    "attributes"
})
public class ProvisionType
    extends WorkflowTaskType
{

    protected ListType attributes;
    @XmlAttribute(name = "sync")
    protected Boolean sync;
    @XmlAttribute(name = "target")
    protected String target;
    @XmlAttribute(name = "setPassword")
    protected Boolean setPassword;
    @XmlAttribute(name = "onlyPassedInAttributes")
    protected Boolean onlyPassedInAttributes;

    /**
     * Gets the value of the attributes property.
     * 
     * @return
     *     possible object is
     *     {@link ListType }
     *     
     */
    public ListType getAttributes() {
        return attributes;
    }

    /**
     * Sets the value of the attributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link ListType }
     *     
     */
    public void setAttributes(ListType value) {
        this.attributes = value;
    }

    /**
     * Gets the value of the sync property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isSync() {
        return sync;
    }

    /**
     * Sets the value of the sync property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setSync(Boolean value) {
        this.sync = value;
    }

    /**
     * Gets the value of the target property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTarget() {
        return target;
    }

    /**
     * Sets the value of the target property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTarget(String value) {
        this.target = value;
    }

    /**
     * Gets the value of the setPassword property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isSetPassword() {
        if (setPassword == null) {
            return false;
        } else {
            return setPassword;
        }
    }

    /**
     * Sets the value of the setPassword property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setSetPassword(Boolean value) {
        this.setPassword = value;
    }

    /**
     * Gets the value of the onlyPassedInAttributes property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isOnlyPassedInAttributes() {
        if (onlyPassedInAttributes == null) {
            return false;
        } else {
            return onlyPassedInAttributes;
        }
    }

    /**
     * Sets the value of the onlyPassedInAttributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setOnlyPassedInAttributes(Boolean value) {
        this.onlyPassedInAttributes = value;
    }

}
