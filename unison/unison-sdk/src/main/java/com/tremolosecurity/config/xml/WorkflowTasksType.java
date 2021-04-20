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
// Generated on: 2021.04.19 at 02:09:41 PM EDT 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for workflowTasksType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="workflowTasksType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;group ref="{http://www.tremolosecurity.com/tremoloConfig}workflowTasksGroup" maxOccurs="unbounded" minOccurs="0"/>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "workflowTasksType", propOrder = {
    "workflowTasksGroup"
})
public class WorkflowTasksType {

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

}
