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
// Generated on: 2015.09.05 at 08:30:41 PM EDT 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlType;


/**
 * A workflow is a series of tasks and decisions to update downstream identity stores
 * 
 * <p>Java class for workflowType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="workflowType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;group ref="{http://www.tremolosecurity.com/tremoloConfig}workflowTasksGroup" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;attribute name="name" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="label" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="description" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="inList" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="orgid" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "workflowType", propOrder = {
    "workflowTasksGroup"
})
public class WorkflowType {

    @XmlElements({
        @XmlElement(name = "provision", type = ProvisionType.class),
        @XmlElement(name = "ifNotUserExists", type = IfNotUserExistsType.class),
        @XmlElement(name = "addGroup", type = AddGroupType.class),
        @XmlElement(name = "resync", type = ResyncType.class),
        @XmlElement(name = "ifAttrHasValue", type = IfAttrHasValueType.class),
        @XmlElement(name = "ifAttrExists", type = IfAttrExistsType.class),
        @XmlElement(name = "addAttribute", type = AddAttributeType.class),
        @XmlElement(name = "mapping", type = MappingType.class),
        @XmlElement(name = "approval", type = ApprovalType.class),
        @XmlElement(name = "callWorkflow", type = CallWorkflowType.class),
        @XmlElement(name = "notifyUser", type = NotifyUserType.class),
        @XmlElement(name = "customTask", type = CustomTaskType.class),
        @XmlElement(name = "delete", type = DeleteType.class)
    })
    protected List<WorkflowTaskType> workflowTasksGroup;
    @XmlAttribute(name = "name")
    protected String name;
    @XmlAttribute(name = "label")
    protected String label;
    @XmlAttribute(name = "description")
    protected String description;
    @XmlAttribute(name = "inList")
    protected Boolean inList;
    @XmlAttribute(name = "orgid")
    protected String orgid;

    /**
     * Gets the value of the workflowTasksGroup property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the workflowTasksGroup property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getWorkflowTasksGroup().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ProvisionType }
     * {@link IfNotUserExistsType }
     * {@link AddGroupType }
     * {@link ResyncType }
     * {@link IfAttrHasValueType }
     * {@link IfAttrExistsType }
     * {@link AddAttributeType }
     * {@link MappingType }
     * {@link ApprovalType }
     * {@link CallWorkflowType }
     * {@link NotifyUserType }
     * {@link CustomTaskType }
     * {@link DeleteType }
     * 
     * 
     */
    public List<WorkflowTaskType> getWorkflowTasksGroup() {
        if (workflowTasksGroup == null) {
            workflowTasksGroup = new ArrayList<WorkflowTaskType>();
        }
        return this.workflowTasksGroup;
    }

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setName(String value) {
        this.name = value;
    }

    /**
     * Gets the value of the label property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLabel() {
        return label;
    }

    /**
     * Sets the value of the label property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLabel(String value) {
        this.label = value;
    }

    /**
     * Gets the value of the description property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the value of the description property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDescription(String value) {
        this.description = value;
    }

    /**
     * Gets the value of the inList property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isInList() {
        return inList;
    }

    /**
     * Sets the value of the inList property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setInList(Boolean value) {
        this.inList = value;
    }

    /**
     * Gets the value of the orgid property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOrgid() {
        return orgid;
    }

    /**
     * Sets the value of the orgid property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOrgid(String value) {
        this.orgid = value;
    }

}