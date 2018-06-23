package com.tremolosecurity.openunison.undertow;


/**
 * ErrorPageConfig
 */
public class ErrorPageConfig {
    String location;
    int code;

    public ErrorPageConfig() {

    }


    /**
     * @return the code
     */
    public int getCode() {
        return code;
    }

    /**
     * @return the location
     */
    public String getLocation() {
        return location;
    }

    /**
     * @param code the code to set
     */
    public void setCode(int code) {
        this.code = code;
    }

    /**
     * @param location the location to set
     */
    public void setLocation(String location) {
        this.location = location;
    }
}