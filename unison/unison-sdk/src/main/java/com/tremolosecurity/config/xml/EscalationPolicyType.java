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
// Generated on: 2024.01.30 at 01:24:43 PM EST 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * Provides an optional escalation policy for an approval
 * 			
 * 
 * <p>Java class for escalationPolicyType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="escalationPolicyType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="escalationFailure" type="{http://www.tremolosecurity.com/tremoloConfig}escalationFailureType"/&gt;
 *         &lt;element name="escalation" type="{http://www.tremolosecurity.com/tremoloConfig}escalationType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "escalationPolicyType", propOrder = {
    "escalationFailure",
    "escalation"
})
public class EscalationPolicyType {

    @XmlElement(required = true)
    protected EscalationFailureType escalationFailure;
    protected List<EscalationType> escalation;

    /**
     * Gets the value of the escalationFailure property.
     * 
     * @return
     *     possible object is
     *     {@link EscalationFailureType }
     *     
     */
    public EscalationFailureType getEscalationFailure() {
        return escalationFailure;
    }

    /**
     * Sets the value of the escalationFailure property.
     * 
     * @param value
     *     allowed object is
     *     {@link EscalationFailureType }
     *     
     */
    public void setEscalationFailure(EscalationFailureType value) {
        this.escalationFailure = value;
    }

    /**
     * Gets the value of the escalation property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the Jakarta XML Binding object.
     * This is why there is not a <CODE>set</CODE> method for the escalation property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getEscalation().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link EscalationType }
     * 
     * 
     */
    public List<EscalationType> getEscalation() {
        if (escalation == null) {
            escalation = new ArrayList<EscalationType>();
        }
        return this.escalation;
    }

}
