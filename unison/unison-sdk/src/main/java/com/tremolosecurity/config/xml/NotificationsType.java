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

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for notificationsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="notificationsType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="dynamicNotifications" type="{http://www.tremolosecurity.com/tremoloConfig}dynamicNotificationsType" minOccurs="0"/&gt;
 *         &lt;element name="notification" type="{http://www.tremolosecurity.com/tremoloConfig}notificationType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "notificationsType", propOrder = {
    "dynamicNotifications",
    "notification"
})
public class NotificationsType {

    protected DynamicNotificationsType dynamicNotifications;
    protected List<NotificationType> notification;

    /**
     * Gets the value of the dynamicNotifications property.
     * 
     * @return
     *     possible object is
     *     {@link DynamicNotificationsType }
     *     
     */
    public DynamicNotificationsType getDynamicNotifications() {
        return dynamicNotifications;
    }

    /**
     * Sets the value of the dynamicNotifications property.
     * 
     * @param value
     *     allowed object is
     *     {@link DynamicNotificationsType }
     *     
     */
    public void setDynamicNotifications(DynamicNotificationsType value) {
        this.dynamicNotifications = value;
    }

    /**
     * Gets the value of the notification property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the notification property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getNotification().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link NotificationType }
     * 
     * 
     */
    public List<NotificationType> getNotification() {
        if (notification == null) {
            notification = new ArrayList<NotificationType>();
        }
        return this.notification;
    }

}
