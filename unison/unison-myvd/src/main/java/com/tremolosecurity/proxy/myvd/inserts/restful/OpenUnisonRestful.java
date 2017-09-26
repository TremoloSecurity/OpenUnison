/*
 * Copyright 2017 Tremolo Security, Inc.
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
 */

package com.tremolosecurity.proxy.myvd.inserts.restful;

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.novell.ldap.*;
import com.novell.ldap.util.DN;
import com.tremolosecurity.lastmile.LastMile;
import com.tremolosecurity.ldapJson.LdapJsonBindRequest;
import com.tremolosecurity.ldapJson.LdapJsonEntry;
import com.tremolosecurity.ldapJson.LdapJsonError;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import net.sourceforge.myvd.chain.*;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.*;
import net.sourceforge.myvd.util.IteratorEntrySet;
import net.sourceforge.myvd.util.NamingUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.joda.time.DateTime;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class OpenUnisonRestful implements Insert {
    String baseDN;

    String name;
    private DistinguishedName localBase;
    private DN remoteBase;
    NamingUtils utils;
    private String[] explodedRemoteBase;
    private String[] explodedLocalBase;
    String urlBase;
    static Gson gson = new Gson();

    String uriPath;

    String callAsUserID;
    String lastMileKeyName;
    String callAsUserIDAttributeName;
    private com.tremolosecurity.saml.Attribute lastMileAttribute;

    @Override
    public String getName() {
        return name;
    }

    protected DN getRemoteMappedDN(DN dn) {

        //if ((dn.getRDNs().size() < this.explodedLocalBase.length) || (dn.equals(this.localBase.getDN()) || dn.isDescendantOf(this.localBase.getDN()))) {
        return utils.getRemoteMappedDN(dn,explodedLocalBase,explodedRemoteBase);
        //} else {
        //	return dn;
        //}
    }

    protected DN getLocalMappedDN(DN dn) {
        return utils.getLocalMappedDN(dn,explodedRemoteBase,explodedLocalBase);

    }

    @Override
    public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
        this.name = name;
        this.baseDN = props.getProperty("remoteBase");
        this.localBase = nameSpace.getBase();
        this.remoteBase = new DN(props.getProperty("remoteBase"));
        this.explodedRemoteBase = this.remoteBase.explodeDN(false);
        this.explodedLocalBase = nameSpace.getBase().getDN().explodeDN(false);
        this.urlBase = props.getProperty("urlBase");
        this.uriPath = props.getProperty("uriPath");
        this.utils = new NamingUtils();

        this.callAsUserID = props.getProperty("callAsUserID");
        this.callAsUserIDAttributeName = props.getProperty("callAsUserIDAttributeName");
        this.lastMileKeyName = props.getProperty("lastMileKeyName");
        this.lastMileAttribute = new com.tremolosecurity.saml.Attribute(this.callAsUserIDAttributeName,this.callAsUserID);

    }

    @Override
    public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Not supported");
    }

    @Override
    public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints) throws LDAPException {
        String localBindDN = this.getRemoteMappedDN(dn.getDN()).toString();

        HttpCon con;
        try {
            con = this.createClient();
        } catch (Exception e) {
            throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Could not create connection",e);
        }

        try {
            LdapJsonBindRequest bindRequest = new LdapJsonBindRequest();
            bindRequest.setPassword(new String(pwd.getValue()));
            StringBuffer b = new StringBuffer();
            b.append(this.uriPath).append('/').append(URLEncoder.encode(localBindDN,"UTF-8"));

            StringBuffer urlBuffer = new StringBuffer();
            urlBuffer.append(this.urlBase);
            urlBuffer.append(b);


            HttpPost post = new HttpPost(urlBuffer.toString());

            this.addAuthorizationHeader(b.toString(),post);




            StringEntity str = new StringEntity(gson.toJson(bindRequest), ContentType.APPLICATION_JSON);
            post.setEntity(str);

            HttpResponse resp = con.getHttp().execute(post);

            String json = EntityUtils.toString(resp.getEntity());
            LdapJsonError ldapResponse = gson.fromJson(json,LdapJsonError.class);
            if (ldapResponse.getResponseCode() != 0) {
                throw new LDAPException(LDAPException.resultCodeToString(ldapResponse.getResponseCode()),ldapResponse.getResponseCode(),ldapResponse.getErrorMessage());
            }
        } catch (LDAPException e) {
            throw e;
        } catch (Exception e) {
            throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Could not create connection",e);
        } finally {
            if (con != null) {
                try {
                    con.getHttp().close();
                } catch (IOException e) {
                    //no point
                }
                con.getBcm().close();
            }

        }

    }

    @Override
    public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Not supported");
    }

    @Override
    public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Not supported");
    }

    @Override
    public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Not supported");
    }

    @Override
    public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Not supported");
    }

    @Override
    public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints) throws LDAPException {
        String localBindDN = this.getRemoteMappedDN(base.getDN()).toString();

        HttpCon con;
        try {
            con = this.createClient();
        } catch (Exception e) {
            throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Could not create connection",e);
        }

        try {

            String searchScope;

            switch (scope.getValue()) {
                case 0 : searchScope = "base"; break;
                case 1 : searchScope = "one"; break;
                case 2 : searchScope = "sub"; break;
                default:
                    throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Unknown search scope : " + scope.getValue());
            }

            StringBuffer b = new StringBuffer();
            b.append(this.uriPath).append('/')
                    .append(URLEncoder.encode(localBindDN,"UTF-8"))
                    .append('/')
                    .append(URLEncoder.encode(searchScope,"UTF-8"));






            StringBuffer urlBuffer = new StringBuffer();
            urlBuffer.append(this.urlBase).append(b);

            urlBuffer.append("?filter=").append(URLEncoder.encode(filter.getRoot().toString(),"UTF-8"));

            for (Attribute attribute : attributes) {
                urlBuffer.append("&attributes=").append(URLEncoder.encode(attribute.getAttribute().getName(),"UTF-8"));
            }

            HttpGet get = new HttpGet(urlBuffer.toString());

            this.addAuthorizationHeader(b.toString(),get);




            HttpResponse resp = con.getHttp().execute(get);

            String json = EntityUtils.toString(resp.getEntity());

            if (resp.getStatusLine().getStatusCode() == 200) {
                ArrayList<Entry> toReturn = new ArrayList<Entry>();
                Type listType = new TypeToken<List<LdapJsonEntry>>() {}.getType();

                List<LdapJsonEntry> returned = gson.fromJson(json,listType);
                for (LdapJsonEntry fromServer : returned) {
                    LDAPAttributeSet attrs = new LDAPAttributeSet();
                    for (String attrName : fromServer.getAttrs().keySet()) {
                        LDAPAttribute attr = new LDAPAttribute(attrName);
                        for (String value : fromServer.getAttrs().get(attrName)) {
                            attr.addValue(value);
                        }
                        attrs.add(attr);
                    }
                    LDAPEntry ldapEntry = new LDAPEntry(this.getLocalMappedDN(new DN(fromServer.getDn())).toString(),attrs);
                    toReturn.add(new Entry(ldapEntry));
                }

                chain.addResult(results,new IteratorEntrySet(toReturn.iterator()),base,scope,filter,attributes,typesOnly,constraints);


            } else {
                LdapJsonError ldapResponse = gson.fromJson(json,LdapJsonError.class);
                throw new LDAPException(LDAPException.resultCodeToString(ldapResponse.getResponseCode()),ldapResponse.getResponseCode(),ldapResponse.getErrorMessage());
            }
        } catch (LDAPException e) {
            throw e;
        } catch (Exception e) {
            throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Could not create connection",e);
        } finally {
            if (con != null) {
                try {
                    con.getHttp().close();
                } catch (IOException e) {
                    //no point
                }
                con.getBcm().close();
            }

        }
    }

    @Override
    public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Not supported");
    }

    @Override
    public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Not supported");
    }

    @Override
    public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
        chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
    }

    @Override
    public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
        chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);
    }

    @Override
    public void shutdown() {

    }

    public HttpCon createClient() throws Exception {
        ArrayList<Header> defheaders = new ArrayList<Header>();
        defheaders.add(new BasicHeader("X-Csrf-Token", "1"));



        BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
                GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());

        RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
                .build();

        CloseableHttpClient http = HttpClients.custom()
                .setConnectionManager(bhcm)
                .setDefaultHeaders(defheaders)
                .setDefaultRequestConfig(rc)
                .build();

        HttpCon con = new HttpCon();
        con.setBcm(bhcm);
        con.setHttp(http);

        return con;

    }

    public void addAuthorizationHeader(String uri, HttpRequestBase request) throws Exception {
        LastMile lastMile = new LastMile(uri, DateTime.now().minus(30000),DateTime.now().plus(30000),0,"");
        lastMile.getAttributes().add(this.lastMileAttribute);
        StringBuffer b = new StringBuffer();
        b.append("Bearer: ").append(lastMile.generateLastMileToken(GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(this.lastMileKeyName)));
        request.addHeader("Authorization",b.toString());
    }
}

