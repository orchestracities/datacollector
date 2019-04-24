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

import com.streamsets.datacollector.util.Configuration;
import com.streamsets.lib.security.http.AbstractSSOAuthenticator;
import com.streamsets.lib.security.http.SSOAuthenticationUser;
import com.streamsets.lib.security.http.SSOConstants;
import com.streamsets.lib.security.http.SSOPrincipalUtils;
import com.streamsets.lib.security.http.SSOService;
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class OIDCAuthenticator extends AbstractSSOAuthenticator {
  private static final Logger LOG = LoggerFactory.getLogger(OIDCAuthenticator.class);

  private final OIDCUserAuthenticator userAuthenticator;
  private final OIDCAppAuthenticator appAuthenticator;

  public OIDCAuthenticator(String appContext, SSOService ssoService, Configuration configuration) {
    super(ssoService);
    userAuthenticator = new OIDCUserAuthenticator(getSsoService(), configuration);
    appAuthenticator = new OIDCAppAuthenticator(getSsoService());
  }

  @Override
  protected Logger getLog() {
    return LOG;
  }

  Authentication validateRequestDelegation(ServletRequest request, ServletResponse response, boolean mandatory)
      throws ServerAuthException {
    Authenticator auth = userAuthenticator;
    HttpServletRequest httpReq = (HttpServletRequest) request;
    boolean isRestCall = httpReq.getHeader(SSOConstants.X_REST_CALL) != null;
    boolean isAppCall = httpReq.getHeader(SSOConstants.X_APP_AUTH_TOKEN) != null ||
        httpReq.getHeader(SSOConstants.X_APP_COMPONENT_ID) != null;
    if (isAppCall && isRestCall) {
      auth = appAuthenticator;
      if (getLog().isTraceEnabled()) {
        getLog().trace("App request '{}'", getRequestInfoForLogging(httpReq, "?"));
      }
    } else {
      if (getLog().isTraceEnabled()) {
        getLog().trace("User request '{}'", getRequestInfoForLogging(httpReq, "?"));
      }
    }
    return auth.validateRequest(request, response, mandatory);
  }


  @Override
  public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory)
      throws ServerAuthException {
  	OIDCPrincipalJson.resetRequestIpAddress();
    Authentication authentication = validateRequestDelegation(request, response, mandatory);
/*    if (authentication instanceof OIDCAuthenticationUser) {
      // if the Authentication is an authenticated user, we set the IP address of the request in it.
      SSOPrincipalUtils.setRequestInfo(((OIDCAuthenticationUser)authentication).getSSOUserPrincipal(), request);
    }*/
    return authentication;
  }


}
