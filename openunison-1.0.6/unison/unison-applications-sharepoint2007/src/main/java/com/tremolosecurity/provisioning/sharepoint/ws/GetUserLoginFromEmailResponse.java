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
 *         &lt;element name="GetUserLoginFromEmailResult" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="GetUserLoginFromEmail">
 *                     &lt;complexType>
 *                       &lt;complexContent>
 *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                           &lt;sequence>
 *                             &lt;element name="User" type="{http://schemas.microsoft.com/sharepoint/soap/directory/}User"/>
 *                           &lt;/sequence>
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
@XmlType(name = "", propOrder = {
    "getUserLoginFromEmailResult"
})
@XmlRootElement(name = "GetUserLoginFromEmailResponse")
public class GetUserLoginFromEmailResponse {

    @XmlElement(name = "GetUserLoginFromEmailResult")
    protected GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult getUserLoginFromEmailResult;

    /**
     * Gets the value of the getUserLoginFromEmailResult property.
     * 
     * @return
     *     possible object is
     *     {@link GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult }
     *     
     */
    public GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult getGetUserLoginFromEmailResult() {
        return getUserLoginFromEmailResult;
    }

    /**
     * Sets the value of the getUserLoginFromEmailResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult }
     *     
     */
    public void setGetUserLoginFromEmailResult(GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult value) {
        this.getUserLoginFromEmailResult = value;
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
     *         &lt;element name="GetUserLoginFromEmail">
     *           &lt;complexType>
     *             &lt;complexContent>
     *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *                 &lt;sequence>
     *                   &lt;element name="User" type="{http://schemas.microsoft.com/sharepoint/soap/directory/}User"/>
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
        "getUserLoginFromEmail"
    })
    public static class GetUserLoginFromEmailResult {

        @XmlElement(name = "GetUserLoginFromEmail", required = true)
        protected GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult.GetUserLoginFromEmail getUserLoginFromEmail;

        /**
         * Gets the value of the getUserLoginFromEmail property.
         * 
         * @return
         *     possible object is
         *     {@link GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult.GetUserLoginFromEmail }
         *     
         */
        public GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult.GetUserLoginFromEmail getGetUserLoginFromEmail() {
            return getUserLoginFromEmail;
        }

        /**
         * Sets the value of the getUserLoginFromEmail property.
         * 
         * @param value
         *     allowed object is
         *     {@link GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult.GetUserLoginFromEmail }
         *     
         */
        public void setGetUserLoginFromEmail(GetUserLoginFromEmailResponse.GetUserLoginFromEmailResult.GetUserLoginFromEmail value) {
            this.getUserLoginFromEmail = value;
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
         *         &lt;element name="User" type="{http://schemas.microsoft.com/sharepoint/soap/directory/}User"/>
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
            "user"
        })
        public static class GetUserLoginFromEmail {

            @XmlElement(name = "User", required = true)
            protected User user;

            /**
             * Gets the value of the user property.
             * 
             * @return
             *     possible object is
             *     {@link User }
             *     
             */
            public User getUser() {
                return user;
            }

            /**
             * Sets the value of the user property.
             * 
             * @param value
             *     allowed object is
             *     {@link User }
             *     
             */
            public void setUser(User value) {
                this.user = value;
            }

        }

    }

}
