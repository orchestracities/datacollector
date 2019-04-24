/*
 * Copyright 2017 StreamSets Inc.
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
package com.streamsets.lib.security.http.oidc;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.streamsets.datacollector.util.Configuration;
import com.streamsets.lib.security.http.RestClient;
import com.streamsets.lib.security.http.RestClient.Builder;
import com.streamsets.lib.security.http.RestClient.Response;
import com.streamsets.lib.security.http.oidc.DiscoveryJson;
import com.streamsets.lib.security.http.oidc.OIDCPrincipalJson;
import com.streamsets.lib.security.http.oidc.OIDCService;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.IOException;
import sun.net.www.protocol.http.HttpURLConnection;
import java.util.Collections;
import java.util.Map;

public class TestOIDCService {

  @Test
  public void testCustomConfigs() throws Exception {
    OIDCService service = Mockito.spy(new OIDCService());

    Configuration conf = new Configuration();
    conf.set(OIDCService.OIDC_AUTHORIZATION_URL_CONFIG, "http://foo/auth");
    conf.set(OIDCService.OIDC_END_SESSION_URL_CONFIG, "http://foo/logout");
    conf.set(OIDCService.OIDC_TOKEN_URL_CONFIG, "http://foo/token");
    conf.set(OIDCService.OIDC_TOKEN_INTROSPECTION_URL_CONFIG, "http://foo/introspection");
    conf.set(OIDCService.OIDC_USER_INFO_URL_CONFIG, "http://foo/user");
    conf.set(OIDCService.SECURITY_CLIENT_ID_CONFIG, "client");
    conf.set(OIDCService.SECURITY_CLIENT_SECRET_CONFIG, "secret");
    
    conf.set(OIDCService.SECURITY_SERVICE_VALIDATE_AUTH_TOKEN_FREQ_CONFIG, 30);
    conf.set(OIDCService.SECURITY_SERVICE_CONNECTION_TIMEOUT_CONFIG, 2000);
    service.setConfiguration(conf);
    Assert.assertEquals("http://foo/auth", service.getLoginPageUrl());
    Assert.assertEquals("http://foo/logout", service.getLogoutUrl());
    Assert.assertEquals(2000, service.getConnectionTimeout());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testLowValidateAuthTokenFrequency() throws Exception {
    OIDCService service = Mockito.spy(new OIDCService());

    Configuration conf = new Configuration();
    conf.set(OIDCService.SECURITY_CLIENT_ID_CONFIG, "serviceComponentId");
    conf.set(OIDCService.SECURITY_SERVICE_VALIDATE_AUTH_TOKEN_FREQ_CONFIG, 29);
    conf.set(OIDCService.SECURITY_SERVICE_CONNECTION_TIMEOUT_CONFIG, 2000);
    service.setConfiguration(conf);
  }

  //FIXME something wrong in the mockup tests
  @Test
  public void testDiscoveryConfigs() throws Exception {

    OIDCService service = Mockito.spy(new OIDCService());
    
    DiscoveryJson discovery = TestDiscoveryJSON.createOIDCDiscovery();
    
    RestClient.Response response = Mockito.mock(RestClient.Response.class);
    RestClient restClient = Mockito.mock(RestClient.class);
    RestClient.Builder builder = Mockito.mock(RestClient.Builder.class);

    Mockito.doReturn(restClient).when(builder).build();
    Mockito.doReturn(builder).when(service).getDiscoveryClientBuilder();
    Mockito.doReturn(response).when(restClient).get();
    // valid discovery
    Mockito.when(response.getStatus()).thenReturn(HttpURLConnection.HTTP_OK);
    Mockito.when(response.getData(Mockito.eq(  DiscoveryJson.class))).thenReturn(discovery);
    
    
    Configuration conf = new Configuration();
    conf.set(OIDCService.OIDC_DISCOVERY_URL_CONFIG, "https://discovery");
    
    service.setConfiguration(conf);
    
    Assert.assertEquals("https://auth", service.getLoginPageUrl());
    Assert.assertEquals("https://end", service.getLogoutUrl());
  }
  

  @Test
  public void testValidateUserTokenWithSecurityService() throws Exception {
    Configuration conf = new Configuration();
    conf.set(OIDCService.OIDC_AUTHORIZATION_URL_CONFIG, "http://foo/auth");
    conf.set(OIDCService.OIDC_END_SESSION_URL_CONFIG, "http://foo/logout");
    conf.set(OIDCService.OIDC_TOKEN_URL_CONFIG, "http://foo/token");
    conf.set(OIDCService.OIDC_TOKEN_INTROSPECTION_URL_CONFIG, "http://foo/introspection");
    conf.set(OIDCService.OIDC_USER_INFO_URL_CONFIG, "http://foo/user");
    conf.set(OIDCService.SECURITY_CLIENT_ID_CONFIG, "client");
    conf.set(OIDCService.SECURITY_CLIENT_SECRET_CONFIG, "secret");
    
    OIDCService service = Mockito.spy(new OIDCService());
    service.setConfiguration(conf);
    Mockito.doReturn(true).when(service).checkServiceActive();

    OIDCPrincipalJson principal = TestOIDCPrincipalJson.createPrincipal();

    RestClient.Response response = Mockito.mock(RestClient.Response.class);
    RestClient restClient = Mockito.mock(RestClient.class);
    RestClient.Builder builder = Mockito.mock(RestClient.Builder.class);
    Mockito.doReturn(restClient).when(builder).build();
    Mockito.doReturn(builder).when(service).getUserAuthClientBuilder();
    Mockito.doReturn(builder).when(builder).header("Content-Type", "application/x-www-form-urlencoded");
    Mockito.doReturn(response).when(restClient).post(Mockito.any());

    // valid token
    Mockito.when(response.getStatus()).thenReturn(HttpURLConnection.HTTP_OK);
    Mockito.when(response.getData(Mockito.eq( OIDCPrincipalJson.class))).thenReturn(principal);

    Assert.assertEquals(principal, service.validateUserTokenWithSecurityService("foo"));
    Assert.assertEquals("foo", principal.getTokenStr());

    // invalid token

    Mockito.when(response.getData(Mockito.eq(OIDCPrincipalJson.class))).thenReturn(null);

    Assert.assertNull(service.validateUserTokenWithSecurityService("foo"));
  }


  
  @Test
  public void testValidateAppTokenWithSecurityService() throws Exception {
    Configuration conf = new Configuration();
    conf.set(OIDCService.OIDC_AUTHORIZATION_URL_CONFIG, "http://foo/auth");
    conf.set(OIDCService.OIDC_END_SESSION_URL_CONFIG, "http://foo/logout");
    conf.set(OIDCService.OIDC_TOKEN_URL_CONFIG, "http://foo/token");
    conf.set(OIDCService.OIDC_TOKEN_INTROSPECTION_URL_CONFIG, "http://foo/introspection");
    conf.set(OIDCService.OIDC_USER_INFO_URL_CONFIG, "http://foo/user");
    conf.set(OIDCService.SECURITY_CLIENT_ID_CONFIG, "client");
    conf.set(OIDCService.SECURITY_CLIENT_SECRET_CONFIG, "secret");
    
    OIDCService service = Mockito.spy(new OIDCService());
    service.setConfiguration(conf);
    Mockito.doReturn(true).when(service).checkServiceActive();

    OIDCPrincipalJson principal = TestOIDCPrincipalJson.createPrincipal();

    RestClient.Response response = Mockito.mock(RestClient.Response.class);
    RestClient restClient = Mockito.mock(RestClient.class);
    RestClient.Builder builder = Mockito.mock(RestClient.Builder.class);
    Mockito.doReturn(restClient).when(builder).build();
    Mockito.doReturn(builder).when(service).getAppAuthClientBuilder();
    Mockito.doReturn(builder).when(builder).header("Content-Type", "application/x-www-form-urlencoded");
    Mockito.doReturn(response).when(restClient).post(Mockito.any());

    // valid token
    Mockito.when(response.getStatus()).thenReturn(HttpURLConnection.HTTP_OK);
    Mockito.when(response.getData(Mockito.eq( OIDCPrincipalJson.class))).thenReturn(principal);

    Assert.assertEquals(principal, service.validateAppTokenWithSecurityService("foo", "client"));
    Assert.assertEquals("foo", principal.getTokenStr());

    // invalid token

    Mockito.when(response.getData(Mockito.eq(OIDCPrincipalJson.class))).thenReturn(null);

    Assert.assertNull(service.validateAppTokenWithSecurityService("foo", "client"));
  }

  @Test
  public void testServiceActive() throws Exception {
    Configuration conf = new Configuration();
    conf.set(OIDCService.OIDC_DISCOVERY_URL_CONFIG, "https://discovery");
    OIDCService service = Mockito.spy(new OIDCService());
    RestClient.Response response = Mockito.mock(RestClient.Response.class);
    RestClient restClient = Mockito.mock(RestClient.class);
    RestClient.Builder builder = Mockito.mock(RestClient.Builder.class);
    DiscoveryJson discovery = TestDiscoveryJSON.createOIDCDiscovery();
    Mockito.doReturn(restClient).when(builder).build();
    Mockito.doReturn(builder).when(service).getDiscoveryClientBuilder();
    Mockito.doReturn(response).when(restClient).get();
    Mockito.when(response.getStatus()).thenReturn(HttpURLConnection.HTTP_OK);
    Mockito.when(response.getData(Mockito.eq(  DiscoveryJson.class))).thenReturn(discovery);
    
    service.setConfiguration(conf);

    Assert.assertFalse(service.isServiceActive(false));
    Mockito.verify(service, Mockito.never()).checkServiceActive();
    Mockito.verify(service, Mockito.never()).getLoginPageUrl();
    Assert.assertFalse(service.isServiceActive(true));
    Mockito.verify(service, Mockito.times(1)).checkServiceActive();
    Mockito.verify(service, Mockito.times(1)).getLoginPageUrl();
  }

}
