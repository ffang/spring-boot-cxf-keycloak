/**
 *  Copyright 2005-2016 Red Hat, Inc.
 *
 *  Red Hat licenses this file to you under the Apache License, version
 *  2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.  See the License for the specific language governing
 *  permissions and limitations under the License.
 */
package io.fabric8.quickstarts.cxf.jaxrs;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;


import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;


import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxrs.client.spec.ClientImpl.WebTargetImpl;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;


import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.util.BasicAuthHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class IntegrationTest {

    public static Logger LOG = LoggerFactory.getLogger(IntegrationTest.class);
    
    static String JAXRS_URL = "http://localhost:8080/services/helloservice/sayHello/FIS";
    static String SSO_URL = System.getProperty("sso.server", "http://localhost:8180");
    
    CloseableHttpClient httpClient;
   

    @BeforeClass
    public static void beforeClass() {
        
    }

    @BeforeClass
    public static void initLogging() {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    @AfterClass
    public static void cleanupLogging() {
        SLF4JBridgeHandler.uninstall();
    }


    @Test
    public void testRestClientWithKeyCloakToken() throws Exception {

        String accessToken = fetchAccessToken();

        Client client = ClientBuilder.newClient().register(JacksonJsonProvider.class)
            .register(LoggingFeature.class);

        
        WebTargetImpl target = (WebTargetImpl)client.target(JAXRS_URL);
        
        String response = target.request().header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .get(String.class);
        Assert.assertEquals("Hello FIS, Welcome to CXF RS Spring Boot World!!!", response);

    }
    
    
    @Test
    public void testRestClientWithInvalidKeyCloakToken() throws Exception {

        String accessToken = fetchAccessToken();

        Client client = ClientBuilder.newClient().register(JacksonJsonProvider.class)
            .register(LoggingFeature.class);

        try {
            WebTargetImpl target = (WebTargetImpl)client.target(JAXRS_URL);
        
            target.request().header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken + "intendwrong")
                .get(String.class);
            fail("Should receive HTTP 401 Unauthorized with incorrect access token so can't pass RH SSO authentication");
        } catch (javax.ws.rs.NotAuthorizedException ex) {
            assertTrue(ex.getMessage().contains("HTTP 401 Unauthorized"));
        }


    }
    
   
    

    private String fetchAccessToken()
        throws UnsupportedEncodingException, IOException, ClientProtocolException {
        String accessToken = null;

        try (CloseableHttpClient client = getCloseableHttpClient()) {
            // "4.3. Resource Owner Password Credentials Grant"
            // from https://tools.ietf.org/html/rfc6749#section-4.3
            // we use "resource owner" credentials directly to obtain the token
            HttpPost post = new HttpPost(SSO_URL
                                         + "/auth/realms/camel-soap-rest-bridge/protocol/openid-connect/token");
            LinkedList<NameValuePair> params = new LinkedList<>();
            params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
            params.add(new BasicNameValuePair("username", "admin"));
            params.add(new BasicNameValuePair("password", "passw0rd"));
            UrlEncodedFormEntity postData = new UrlEncodedFormEntity(params);
            post.setEntity(postData);

            String basicAuth = BasicAuthHelper.createHeader("camel-bridge",
                                                            "f1ec716d-2262-434d-8e98-bf31b6b858d6");
            post.setHeader("Authorization", basicAuth);
            CloseableHttpResponse response = client.execute(post);

            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(response.getEntity().getContent());
            if (json.get("error") == null) {
                accessToken = json.get("access_token").asText();
                LOG.info("token: {}", accessToken);
            } else {
                LOG.warn("error: {}, description: {}", json.get("error"), json.get("error_description"));
                fail();
            }
            response.close();
        }
        return accessToken;
    }

    
    /**
     * Since Openshift self-signed certificate can't have accurate
     * hostname of the service, we don't check the hostname match in certificate
     * in the quickstart, and shouldn't use this in production
     */
    private CloseableHttpClient getCloseableHttpClient() {
        if (httpClient != null) {
            return httpClient;
        }
        
        return HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
       
      
    }
     
}