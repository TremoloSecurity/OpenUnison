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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


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
 *         &lt;element name="GetGroupCollectionFromUserResult" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="GetGroupCollectionFromUser" type="{http://schemas.microsoft.com/sharepoint/soap/directory/}GetGroupCollectionFromUserType" minOccurs="0"/>
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
@XmlType(name = "", propOrder = {
    "getGroupCollectionFromUserResult"
})
@XmlRootElement(name = "GetGroupCollectionFromUserResponse")
public class GetGroupCollectionFromUserResponse {

    @XmlElement(name = "GetGroupCollectionFromUserResult")
    protected GetGroupCollectionFromUserResponse.GetGroupCollectionFromUserResult getGroupCollectionFromUserResult;

    /**
     * Gets the value of the getGroupCollectionFromUserResult property.
     * 
     * @return
     *     possible object is
     *     {@link GetGroupCollectionFromUserResponse.GetGroupCollectionFromUserResult }
     *     
     */
    public GetGroupCollectionFromUserResponse.GetGroupCollectionFromUserResult getGetGroupCollectionFromUserResult() {
        return getGroupCollectionFromUserResult;
    }

    /**
     * Sets the value of the getGroupCollectionFromUserResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetGroupCollectionFromUserResponse.GetGroupCollectionFromUserResult }
     *     
     */
    public void setGetGroupCollectionFromUserResult(GetGroupCollectionFromUserResponse.GetGroupCollectionFromUserResult value) {
        this.getGroupCollectionFromUserResult = value;
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
     *         &lt;element name="GetGroupCollectionFromUser" type="{http://schemas.microsoft.com/sharepoint/soap/directory/}GetGroupCollectionFromUserType" minOccurs="0"/>
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
        "getGroupCollectionFromUser"
    })
    public static class GetGroupCollectionFromUserResult {

        @XmlElement(name = "GetGroupCollectionFromUser")
        protected GetGroupCollectionFromUserType getGroupCollectionFromUser;

        /**
         * Gets the value of the getGroupCollectionFromUser property.
         * 
         * @return
         *     possible object is
         *     {@link GetGroupCollectionFromUserType }
         *     
         */
        public GetGroupCollectionFromUserType getGetGroupCollectionFromUser() {
            return getGroupCollectionFromUser;
        }

        /**
         * Sets the value of the getGroupCollectionFromUser property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetGroupCollectionFromUserType }
         *     
         */
        public void setGetGroupCollectionFromUser(GetGroupCollectionFromUserType value) {
            this.getGroupCollectionFromUser = value;
        }

    }

}
