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

import org.junit.Assert;
import org.junit.Test;

import com.streamsets.lib.security.http.oidc.DiscoveryJson;

public class TestDiscoveryJSON {

  public static DiscoveryJson createOIDCDiscovery() {
	DiscoveryJson bean = new  DiscoveryJson();
	bean.setAuthorizationEndpoint("https://auth");
	bean.setEndSessionEndpoint("https://end");
	bean.setIssuer("https://issuer");
	bean.setTokenEndpoint("https://token");
	bean.setTokenIntrospectionEndpoint("https://introspection");
	bean.setUserinfoEndpoint("https://user");
	return bean;
  }
	
  @Test
  public void testBean() {
	DiscoveryJson bean = new DiscoveryJson();
    bean.setAuthorizationEndpoint("https://auth");
    bean.setEndSessionEndpoint("https://end");
    bean.setIssuer("https://issuer");
    bean.setTokenEndpoint("https://token");
    bean.setTokenIntrospectionEndpoint("https://introspection");
    bean.setUserinfoEndpoint("https://user");
    Assert.assertEquals("https://auth", bean.getAuthorizationEndpoint());
    Assert.assertEquals("https://end", bean.getEndSessionEndpoint());
    Assert.assertEquals("https://issuer", bean.getIssuer());
    Assert.assertEquals("https://token",bean.getTokenEndpoint());
    Assert.assertEquals("https://introspection",bean.getTokenIntrospectionEndpoint());
    Assert.assertEquals("https://user",bean.getUserinfoEndpoint());
  }

}
