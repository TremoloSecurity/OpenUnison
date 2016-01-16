/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/



package com.tremolosecurity.provisioning.sharepoint.ws;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for GetGroupCollectionFromUserType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="GetGroupCollectionFromUserType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="userLoginName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Groups" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Group" maxOccurs="unbounded">
 *                     &lt;complexType>
 *                       &lt;complexContent>
 *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                           &lt;attribute name="ID" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedShort" />
 *                           &lt;attribute name="Name" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *                           &lt;attribute name="Description" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *                           &lt;attribute name="OwnerID" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedByte" />
 *                           &lt;attribute name="OwnerIsUser" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *                         &lt;/restriction>
 *                       &lt;/complexContent>
 *                     &lt;/complexType>
 *                   &lt;/element>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "GetGroupCollectionFromUserType", propOrder = {
    "userLoginName",
    "groups"
})
public class GetGroupCollectionFromUserType {

    protected String userLoginName;
    @XmlElement(name = "Groups")
    protected GetGroupCollectionFromUserType.Groups groups;

    /**
     * Gets the value of the userLoginName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUserLoginName() {
        return userLoginName;
    }

    /**
     * Sets the value of the userLoginName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUserLoginName(String value) {
        this.userLoginName = value;
    }

    /**
     * Gets the value of the groups property.
     * 
     * @return
     *     possible object is
     *     {@link GetGroupCollectionFromUserType.Groups }
     *     
     */
    public GetGroupCollectionFromUserType.Groups getGroups() {
        return groups;
    }

    /**
     * Sets the value of the groups property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetGroupCollectionFromUserType.Groups }
     *     
     */
    public void setGroups(GetGroupCollectionFromUserType.Groups value) {
        this.groups = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="Group" maxOccurs="unbounded">
     *           &lt;complexType>
     *             &lt;complexContent>
     *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *                 &lt;attribute name="ID" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedShort" />
     *                 &lt;attribute name="Name" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
     *                 &lt;attribute name="Description" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
     *                 &lt;attribute name="OwnerID" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedByte" />
     *                 &lt;attribute name="OwnerIsUser" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
     *               &lt;/restriction>
     *             &lt;/complexContent>
     *           &lt;/complexType>
     *         &lt;/element>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "group"
    })
    public static class Groups {

        @XmlElement(name = "Group", required = true)
        protected List<GetGroupCollectionFromUserType.Groups.Group> group;

        /**
         * Gets the value of the group property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the group property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getGroup().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link GetGroupCollectionFromUserType.Groups.Group }
         * 
         * 
         */
        public List<GetGroupCollectionFromUserType.Groups.Group> getGroup() {
            if (group == null) {
                group = new ArrayList<GetGroupCollectionFromUserType.Groups.Group>();
            }
            return this.group;
        }


        /**
         * <p>Java class for anonymous complex type.
         * 
         * <p>The following schema fragment specifies the expected content contained within this class.
         * 
         * <pre>
         * &lt;complexType>
         *   &lt;complexContent>
         *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
         *       &lt;attribute name="ID" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedShort" />
         *       &lt;attribute name="Name" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
         *       &lt;attribute name="Description" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
         *       &lt;attribute name="OwnerID" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedByte" />
         *       &lt;attribute name="OwnerIsUser" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
         *     &lt;/restriction>
         *   &lt;/complexContent>
         * &lt;/complexType>
         * </pre>
         * 
         * 
         */
        @XmlAccessorType(XmlAccessType.FIELD)
        @XmlType(name = "")
        public static class Group {

            @XmlAttribute(name = "ID", required = true)
            @XmlSchemaType(name = "unsignedShort")
            protected int id;
            @XmlAttribute(name = "Name", required = true)
            protected String name;
            @XmlAttribute(name = "Description", required = true)
            protected String description;
            @XmlAttribute(name = "OwnerID", required = true)
            @XmlSchemaType(name = "unsignedByte")
            protected short ownerID;
            @XmlAttribute(name = "OwnerIsUser", required = true)
            protected String ownerIsUser;

            /**
             * Gets the value of the id property.
             * 
             */
            public int getID() {
                return id;
            }

            /**
             * Sets the value of the id property.
             * 
             */
            public void setID(int value) {
                this.id = value;
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
             * Gets the value of the ownerID property.
             * 
             */
            public short getOwnerID() {
                return ownerID;
            }

            /**
             * Sets the value of the ownerID property.
             * 
             */
            public void setOwnerID(short value) {
                this.ownerID = value;
            }

            /**
             * Gets the value of the ownerIsUser property.
             * 
             * @return
             *     possible object is
             *     {@link String }
             *     
             */
            public String getOwnerIsUser() {
                return ownerIsUser;
            }

            /**
             * Sets the value of the ownerIsUser property.
             * 
             * @param value
             *     allowed object is
             *     {@link String }
             *     
             */
            public void setOwnerIsUser(String value) {
                this.ownerIsUser = value;
            }

        }

    }

}
