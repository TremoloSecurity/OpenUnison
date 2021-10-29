/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.10.28 at 08:19:08 PM EDT 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * List of result groups
 * 
 * <p>Java class for resultGroupsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="resultGroupsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="dynamicResultGroups" type="{http://www.tremolosecurity.com/tremoloConfig}dynamicPortalUrlsType" minOccurs="0"/>
 *         &lt;element name="resultGroup" type="{http://www.tremolosecurity.com/tremoloConfig}resultGroupType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "resultGroupsType", propOrder = {
    "dynamicResultGroups",
    "resultGroup"
})
public class ResultGroupsType {

    protected DynamicPortalUrlsType dynamicResultGroups;
    protected List<ResultGroupType> resultGroup;

    /**
     * Gets the value of the dynamicResultGroups property.
     * 
     * @return
     *     possible object is
     *     {@link DynamicPortalUrlsType }
     *     
     */
    public DynamicPortalUrlsType getDynamicResultGroups() {
        return dynamicResultGroups;
    }

    /**
     * Sets the value of the dynamicResultGroups property.
     * 
     * @param value
     *     allowed object is
     *     {@link DynamicPortalUrlsType }
     *     
     */
    public void setDynamicResultGroups(DynamicPortalUrlsType value) {
        this.dynamicResultGroups = value;
    }

    /**
     * Gets the value of the resultGroup property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the resultGroup property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getResultGroup().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ResultGroupType }
     * 
     * 
     */
    public List<ResultGroupType> getResultGroup() {
        if (resultGroup == null) {
            resultGroup = new ArrayList<ResultGroupType>();
        }
        return this.resultGroup;
    }

}
