//
// This file was generated by the Eclipse Implementation of JAXB, v3.0.0 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2024.02.15 at 08:46:42 PM EST 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlType;


/**
 * List of authentication chains
 * 
 * <p>Java class for authChainsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="authChainsType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="dynamicAuthChains" type="{http://www.tremolosecurity.com/tremoloConfig}dynamicPortalUrlsType" minOccurs="0"/&gt;
 *         &lt;element name="chain" type="{http://www.tremolosecurity.com/tremoloConfig}authChainType" maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "authChainsType", propOrder = {
    "dynamicAuthChains",
    "chain"
})
public class AuthChainsType {

    protected DynamicPortalUrlsType dynamicAuthChains;
    protected List<AuthChainType> chain;

    /**
     * Gets the value of the dynamicAuthChains property.
     * 
     * @return
     *     possible object is
     *     {@link DynamicPortalUrlsType }
     *     
     */
    public DynamicPortalUrlsType getDynamicAuthChains() {
        return dynamicAuthChains;
    }

    /**
     * Sets the value of the dynamicAuthChains property.
     * 
     * @param value
     *     allowed object is
     *     {@link DynamicPortalUrlsType }
     *     
     */
    public void setDynamicAuthChains(DynamicPortalUrlsType value) {
        this.dynamicAuthChains = value;
    }

    /**
     * Gets the value of the chain property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the Jakarta XML Binding object.
     * This is why there is not a <CODE>set</CODE> method for the chain property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getChain().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link AuthChainType }
     * 
     * 
     */
    public List<AuthChainType> getChain() {
        if (chain == null) {
            chain = new ArrayList<AuthChainType>();
        }
        return this.chain;
    }

}
