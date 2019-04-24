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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.streamsets.lib.security.http.SSOPrincipal;
import com.streamsets.lib.security.http.oidc.OIDCPrincipalJson;

import org.junit.Assert;
import org.junit.Test;

public class TestOIDCPrincipalJson {

  public static OIDCPrincipalJson createPrincipal() {
    return createPrincipal(System.currentTimeMillis() + 1000);
  }

  public static OIDCPrincipalJson createPrincipal(long expires) {
  	OIDCPrincipalJson p = new OIDCPrincipalJson();
    p.setTokenStr("tokenStr");
    p.setExpires(expires);
    p.setIssuerUrl("issuerUrl");
    p.setPrincipalId("userId");
    p.setPrincipalName("userName");
    p.setEmail("email");
    p.setOrganizationId("orgId");
    p.setOrganizationName("orgName");
    p.getRoles().add("r1");
    p.getAttributes().put("a", "A");
    p.setActive(true);
    return p;
  }

  @Test
  public void testValid() {
  	OIDCPrincipalJson principal =  createPrincipal(1);
    Assert.assertEquals("tokenStr", principal.getTokenStr());
    Assert.assertEquals(1L, principal.getExpires());
    Assert.assertEquals("issuerUrl", principal.getIssuerUrl());
    Assert.assertEquals("userId", principal.getPrincipalId());
    Assert.assertEquals("userId", principal.getName());
    Assert.assertEquals("userName", principal.getPrincipalName());
    Assert.assertEquals("orgId", principal.getOrganizationId());
    Assert.assertEquals("orgName", principal.getOrganizationName());
    Assert.assertEquals("email", principal.getEmail());
    Assert.assertEquals(ImmutableSet.of("r1"), principal.getRoles());
    Assert.assertEquals(ImmutableMap.of("a", "A"), principal.getAttributes());
    Assert.assertEquals(true, principal.isActive());
  }

  @Test(expected = IllegalStateException.class)
  public void testLock() {
  	OIDCPrincipalJson p = new OIDCPrincipalJson();
    p.setPrincipalId("id");
    p.lock();
    p.setPrincipalId("id1");
  }

  @Test
  public void testRequestIpAddress() {
  	OIDCPrincipalJson.resetRequestIpAddress();
    SSOPrincipal principal =  createPrincipal(1);
    Assert.assertNull(principal.getRequestIpAddress());
    ((OIDCPrincipalJson)principal).setRequestIpAddress("foo");
    Assert.assertEquals("foo", principal.getRequestIpAddress());
    OIDCPrincipalJson.resetRequestIpAddress();
    Assert.assertNull(principal.getRequestIpAddress());
  }

}
