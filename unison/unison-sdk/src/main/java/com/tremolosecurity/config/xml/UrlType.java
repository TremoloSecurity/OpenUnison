//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.05.12 at 09:15:45 AM EDT 
//


package com.tremolosecurity.config.xml;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Defines a URL that combines filters, policies,
 * 				authentication and results based on an HTTP URL
 * 
 * <p>Java class for urlType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="urlType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="host" type="{http://www.tremolosecurity.com/tremoloConfig}hostType" maxOccurs="unbounded"/>
 *         &lt;element name="filterChain" type="{http://www.tremolosecurity.com/tremoloConfig}filterChainType"/>
 *         &lt;element name="uri" type="{http://www.tremolosecurity.com/tremoloConfig}uriType"/>
 *         &lt;element name="proxyTo" type="{http://www.tremolosecurity.com/tremoloConfig}proxyToType" minOccurs="0"/>
 *         &lt;element name="results" type="{http://www.tremolosecurity.com/tremoloConfig}resultRefType" minOccurs="0"/>
 *         &lt;element name="azRules" type="{http://www.tremolosecurity.com/tremoloConfig}azRulesType" minOccurs="0"/>
 *         &lt;element name="idp" type="{http://www.tremolosecurity.com/tremoloConfig}idpType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="regex" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="authChain" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="overrideHost" type="{http://www.w3.org/2001/XMLSchema}boolean" default="true" />
 *       &lt;attribute name="overrideReferer" type="{http://www.w3.org/2001/XMLSchema}boolean" default="true" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "urlType", propOrder = {
    "host",
    "filterChain",
    "uri",
    "proxyTo",
    "results",
    "azRules",
    "idp"
})
public class UrlType {

    @XmlElement(required = true)
    protected List<String> host;
    @XmlElement(required = true)
    protected FilterChainType filterChain;
    @XmlElement(required = true)
    protected String uri;
    protected String proxyTo;
    protected ResultRefType results;
    protected AzRulesType azRules;
    protected IdpType idp;
    @XmlAttribute(name = "regex")
    protected Boolean regex;
    @XmlAttribute(name = "authChain")
    protected String authChain;
    @XmlAttribute(name = "overrideHost")
    protected Boolean overrideHost;
    @XmlAttribute(name = "overrideReferer")
    protected Boolean overrideReferer;

    /**
     * Gets the value of the host property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the host property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getHost().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getHost() {
        if (host == null) {
            host = new ArrayList<String>();
        }
        return this.host;
    }

    /**
     * Gets the value of the filterChain property.
     * 
     * @return
     *     possible object is
     *     {@link FilterChainType }
     *     
     */
    public FilterChainType getFilterChain() {
        return filterChain;
    }

    /**
     * Sets the value of the filterChain property.
     * 
     * @param value
     *     allowed object is
     *     {@link FilterChainType }
     *     
     */
    public void setFilterChain(FilterChainType value) {
        this.filterChain = value;
    }

    /**
     * Gets the value of the uri property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUri() {
        return uri;
    }

    /**
     * Sets the value of the uri property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUri(String value) {
        this.uri = value;
    }

    /**
     * Gets the value of the proxyTo property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getProxyTo() {
        return proxyTo;
    }

    /**
     * Sets the value of the proxyTo property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProxyTo(String value) {
        this.proxyTo = value;
    }

    /**
     * Gets the value of the results property.
     * 
     * @return
     *     possible object is
     *     {@link ResultRefType }
     *     
     */
    public ResultRefType getResults() {
        return results;
    }

    /**
     * Sets the value of the results property.
     * 
     * @param value
     *     allowed object is
     *     {@link ResultRefType }
     *     
     */
    public void setResults(ResultRefType value) {
        this.results = value;
    }

    /**
     * Gets the value of the azRules property.
     * 
     * @return
     *     possible object is
     *     {@link AzRulesType }
     *     
     */
    public AzRulesType getAzRules() {
        return azRules;
    }

    /**
     * Sets the value of the azRules property.
     * 
     * @param value
     *     allowed object is
     *     {@link AzRulesType }
     *     
     */
    public void setAzRules(AzRulesType value) {
        this.azRules = value;
    }

    /**
     * Gets the value of the idp property.
     * 
     * @return
     *     possible object is
     *     {@link IdpType }
     *     
     */
    public IdpType getIdp() {
        return idp;
    }

    /**
     * Sets the value of the idp property.
     * 
     * @param value
     *     allowed object is
     *     {@link IdpType }
     *     
     */
    public void setIdp(IdpType value) {
        this.idp = value;
    }

    /**
     * Gets the value of the regex property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isRegex() {
        return regex;
    }

    /**
     * Sets the value of the regex property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setRegex(Boolean value) {
        this.regex = value;
    }

    /**
     * Gets the value of the authChain property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAuthChain() {
        return authChain;
    }

    /**
     * Sets the value of the authChain property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAuthChain(String value) {
        this.authChain = value;
    }

    /**
     * Gets the value of the overrideHost property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isOverrideHost() {
        if (overrideHost == null) {
            return true;
        } else {
            return overrideHost;
        }
    }

    /**
     * Sets the value of the overrideHost property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setOverrideHost(Boolean value) {
        this.overrideHost = value;
    }

    /**
     * Gets the value of the overrideReferer property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isOverrideReferer() {
        if (overrideReferer == null) {
            return true;
        } else {
            return overrideReferer;
        }
    }

    /**
     * Sets the value of the overrideReferer property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setOverrideReferer(Boolean value) {
        this.overrideReferer = value;
    }

}
