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

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class DiscoveryJson {
  private String issuer;
  private String authorizationEndpoint;
  private String tokenEndpoint;
  private String tokenIntrospectionEndpoint;
  private String userInfoEndpoint;
  private String endSessionEndpoint;
  
  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public void setAuthorizationEndpoint(String authorization_endpoint) {
    this.authorizationEndpoint = authorization_endpoint;
  }

  public void setTokenEndpoint(String token_endpoint) {
  	this.tokenEndpoint = token_endpoint;
  }
  
  public void setTokenIntrospectionEndpoint(String token_introspection_endpoint) {
	this.tokenIntrospectionEndpoint = token_introspection_endpoint;
  }
  
  public void setUserinfoEndpoint(String userinfo_endpoint) {
	this.userInfoEndpoint = userinfo_endpoint;
  }
  
  public void setEndSessionEndpoint(String end_session_endpoint) {
	this.endSessionEndpoint = end_session_endpoint;
  }
  
  public String getIssuer() {
    return issuer;
  }

  public String getAuthorizationEndpoint() {
    return authorizationEndpoint;
  }
  
  public String getTokenEndpoint() {
	return tokenEndpoint;
  }
  
  public String getTokenIntrospectionEndpoint() {
	return tokenIntrospectionEndpoint;
  }
  
  public String getUserinfoEndpoint() {
	return userInfoEndpoint;
  }
  
  public String getEndSessionEndpoint() {
	return endSessionEndpoint;
  }
  
}
