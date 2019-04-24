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

import com.google.common.annotations.VisibleForTesting;
import com.streamsets.datacollector.util.Configuration;
import com.streamsets.lib.security.http.AbstractSSOService;
import com.streamsets.lib.security.http.ForbiddenException;
import com.streamsets.lib.security.http.RestClient;
import com.streamsets.lib.security.http.SSOConstants;
import com.streamsets.lib.security.http.SSOPrincipal;
import com.streamsets.pipeline.api.impl.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Map;

public class OIDCService extends AbstractSSOService {
	private static final Logger LOG = LoggerFactory.getLogger(OIDCService.class);

	public static final String CONFIG_PREFIX = "oidc.";
	public static final String OIDC_DISCOVERY_URL_CONFIG = CONFIG_PREFIX + "discoveryUrl";
	public static final String OIDC_AUTHORIZATION_URL_CONFIG = CONFIG_PREFIX + "authorizationEndpoint";
	public static final String OIDC_TOKEN_URL_CONFIG = CONFIG_PREFIX + "tokenEndpoint";
	public static final String OIDC_TOKEN_INTROSPECTION_URL_CONFIG = CONFIG_PREFIX + "tokenIntrospectionEndpoint";
	public static final String OIDC_USER_INFO_URL_CONFIG = CONFIG_PREFIX + "userInfoEndpoint";
	public static final String OIDC_END_SESSION_URL_CONFIG = CONFIG_PREFIX + "endSessionEndpoint";

	public static final String SECURITY_CLIENT_ID_CONFIG = CONFIG_PREFIX + "clientId";
	public static final String SECURITY_CLIENT_SECRET_CONFIG = CONFIG_PREFIX + "clientSecret";
	public static final String SECURITY_SERVICE_CONNECTION_TIMEOUT_CONFIG = CONFIG_PREFIX + "connectionTimeout.millis";

	public static final int DEFAULT_SECURITY_SERVICE_CONNECTION_TIMEOUT = 10000;
	public static final String OIDC_ENABLED = CONFIG_PREFIX + "enabled";
	public static final boolean OIDC_ENABLED_DEFAULT = false;
	public static final String REQUESTED_URL_PARAM = "redirect_uri";
	public static final String CLIENTID_URL_PARAM = "client_id";
	public static final String SCOPE_URL_PARAM = "scope";
	public static final String OIDC_DEFAULT_SCOPE = "profile oidc";
	public static final String RESPONSE_TYPE_URL_PARAM = "response_type";
	public static final String OIDC_DEFAULT_RESPONSE_TYPE = "token";
	
	
	RestClient.Builder discoveryClientBuilder;
	RestClient.Builder userAuthClientBuilder;
	RestClient.Builder appAuthClientBuilder;
	private String clientId;
	private String clientSecret;
	private String discoveryUrl;
	private String authorizationEndpoint;
	private String tokenEndpoint;
	private String tokenIntrospectionEndpoint;
	private String userInfoEndpoint;
	private String logoutEndpoint;
	private String appToken;
	private volatile int connTimeout;
	private volatile boolean serviceActive;

	//TODO make SCOPE configurable / evaluate support for state param in the url.
	
	@Override
	public void setConfiguration(Configuration conf) {
		super.setConfiguration(conf);
		discoveryUrl = conf.get(OIDC_DISCOVERY_URL_CONFIG, null);
		if (discoveryUrl == null || discoveryUrl.isEmpty()) {
			LOG.debug("Discovery URL was NULL");
			authorizationEndpoint = conf.get(OIDC_AUTHORIZATION_URL_CONFIG, null);
			logoutEndpoint = conf.get(OIDC_END_SESSION_URL_CONFIG, null);
			tokenEndpoint = conf.get(OIDC_TOKEN_URL_CONFIG, null);
			tokenIntrospectionEndpoint = conf.get(OIDC_TOKEN_INTROSPECTION_URL_CONFIG, null);
			userInfoEndpoint = conf.get(OIDC_USER_INFO_URL_CONFIG, null);
		} else {
			discoveryClientBuilder = RestClient.builder(discoveryUrl).csrf(true).json(true).timeout(connTimeout);
			try {
				RestClient restClient = getDiscoveryClientBuilder().build();
				RestClient.Response response = restClient.get();
				if (response.getStatus() == HttpURLConnection.HTTP_OK) {
					updateConnectionTimeout(response);
					DiscoveryJson discovery = response.getData(DiscoveryJson.class);
					authorizationEndpoint = discovery.getAuthorizationEndpoint();
					logoutEndpoint = discovery.getEndSessionEndpoint();
					tokenEndpoint = discovery.getTokenEndpoint();
					tokenIntrospectionEndpoint = discovery.getTokenIntrospectionEndpoint();
					userInfoEndpoint = discovery.getUserinfoEndpoint();
					LOG.info("OIDC Discovery completed: {}",discovery.getAuthorizationEndpoint());
				} else {
					throw new RuntimeException(
							Utils.format("Failed OIDC discovery '{}': {}", discoveryUrl, response.getError()));
				}
			} catch (IOException ex) {
				LOG.warn("OIDC Discovery failed: {}", ex.toString());
				ex.printStackTrace();
			}
		}
		clientId = conf.get(SECURITY_CLIENT_ID_CONFIG, null);
		clientSecret = conf.get(SECURITY_CLIENT_SECRET_CONFIG, null);
		setLoginPageUrl(authorizationEndpoint);
		setLogoutUrl(logoutEndpoint);

		Utils.checkArgument(
				authorizationEndpoint.toLowerCase().startsWith("http:")
						|| authorizationEndpoint.toLowerCase().startsWith("https:"),
				Utils.formatL("Security service base URL must be HTTP/HTTPS '{}'", authorizationEndpoint));
		if (authorizationEndpoint.toLowerCase().startsWith("http://")) {
			LOG.warn("Security service base URL is not secure '{}'", authorizationEndpoint);
		}

		connTimeout = conf.get(SECURITY_SERVICE_CONNECTION_TIMEOUT_CONFIG, DEFAULT_SECURITY_SERVICE_CONNECTION_TIMEOUT);

		userAuthClientBuilder = RestClient.builder(tokenIntrospectionEndpoint)
				.csrf(true)
				.json(true)
				.timeout(connTimeout);
		appAuthClientBuilder = RestClient.builder(tokenIntrospectionEndpoint)
				.csrf(true)
				.json(true)
				.timeout(connTimeout); 
	}

	@VisibleForTesting
	public RestClient.Builder getDiscoveryClientBuilder() {
		return discoveryClientBuilder;
	}

	@VisibleForTesting
	public RestClient.Builder getUserAuthClientBuilder() {
		return userAuthClientBuilder;
	}
	
	@VisibleForTesting
	public RestClient.Builder getAppAuthClientBuilder() {
		return appAuthClientBuilder;
	}

	@VisibleForTesting
	void sleep(int secs) {
		try {
			Thread.sleep(secs * 1000);
		} catch (InterruptedException ex) {
			String msg = "Interrupted while attempting DPM registration";
			LOG.error(msg);
			throw new RuntimeException(msg, ex);
		}
	}

	void updateConnectionTimeout(RestClient.Response response) {
		String timeout = response.getHeader(SSOConstants.X_APP_CONNECTION_TIMEOUT);
		connTimeout = (timeout == null) ? connTimeout : Integer.parseInt(timeout);
	}

	protected boolean checkServiceActive() {
		boolean active;
		try {
			URL url = new URL(getLoginPageUrl());
			HttpURLConnection httpURLConnection = ((HttpURLConnection) url.openConnection());
			httpURLConnection.setConnectTimeout(connTimeout);
			httpURLConnection.setReadTimeout(connTimeout);
			int status = httpURLConnection.getResponseCode();
			active = status == HttpURLConnection.HTTP_OK;
			if (!active) {
				LOG.warn("OIDC reachable but returning '{}' HTTP status on login", status);
			}
		} catch (IOException ex) {
			LOG.warn("OIDC not reachable: {}", ex.toString());
			active = false;
		}
		LOG.debug("OIDC current status '{}'", (active) ? "ACTIVE" : "NON ACTIVE");
		return active;
	}

	public boolean isServiceActive(boolean checkNow) {
		if (checkNow) {
			serviceActive = checkServiceActive();
		}
		return serviceActive;
	}

	@Override
	public void register(Map<String, String> attributes) {
		
	}
	
  @Override
  public String createRedirectToLoginUrl(String requestUrl, boolean repeatedRedirect) {
    try {
      String url = getLoginPageUrl() + "?" + REQUESTED_URL_PARAM + "=" + URLEncoder.encode(requestUrl, "UTF-8")
      	+ "&" + RESPONSE_TYPE_URL_PARAM + "=" + URLEncoder.encode(OIDC_DEFAULT_RESPONSE_TYPE, "UTF-8")
      	+ "&" + SCOPE_URL_PARAM + "=" + URLEncoder.encode(OIDC_DEFAULT_SCOPE, "UTF-8")
      	+ "&" + CLIENTID_URL_PARAM + "=" + URLEncoder.encode(clientId, "UTF-8");
      return url;
    } catch (UnsupportedEncodingException ex) {
      throw new RuntimeException(Utils.format("Should not happen: {}", ex.toString()), ex);
    }
  }

 public void setComponentId(String componentId) {

	}

	public void setApplicationAuthToken(String appToken) {
		
	}

	private boolean checkServiceActiveIfInActive() {
		if (!serviceActive) {
			serviceActive = checkServiceActive();
		}
		return serviceActive;
	}

	protected SSOPrincipal validateUserTokenWithSecurityService(String userAuthToken) throws ForbiddenException {
		Utils.checkState(checkServiceActiveIfInActive(), "Security service not active");
		StringBuilder tokenValidationRequest = new StringBuilder();
		try {
			tokenValidationRequest.append(URLEncoder.encode("token", "UTF-8"))
				.append("=")
				.append(URLEncoder.encode(userAuthToken, "UTF-8"));
			if (clientId != null) {
				tokenValidationRequest.append("&")
				.append(URLEncoder.encode("client_id", "UTF-8"))
				.append("=")
				.append(URLEncoder.encode(clientId, "UTF-8"));	
				if (clientSecret != null) {
					tokenValidationRequest.append("&")
					.append(URLEncoder.encode("client_secret", "UTF-8"))
					.append("=")
					.append(URLEncoder.encode(clientSecret, "UTF-8"));
				}
			}
			
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(
					Utils.format("Could not encode user token '{}', message: {}", userAuthToken, e.getMessage())
					);
		}
		
		OIDCPrincipalJson principal;
		try {
			RestClient restClient = getUserAuthClientBuilder().header("Content-Type", "application/x-www-form-urlencoded").build();
			RestClient.Response response = restClient.post(tokenValidationRequest);
			if (response.getStatus() == HttpURLConnection.HTTP_OK) {
				updateConnectionTimeout(response);
				principal = response.getData(OIDCPrincipalJson.class);
			} else if (response.getStatus() == HttpURLConnection.HTTP_FORBIDDEN) {
				throw new ForbiddenException(response.getError());
			} else {
				throw new RuntimeException(
						Utils.format("Could not validate user token '{}', HTTP status '{}' message: {}", null,
								response.getStatus(), response.getError()));
			}
		} catch (IOException ex) {
			LOG.warn("Could not do user token validation, going inactive: {}", ex.toString());
			serviceActive = false;
			throw new RuntimeException(Utils.format("Could not connect to security service: {}", ex), ex);
		}
		if (principal != null) {
			principal.setTokenStr(userAuthToken);
			principal.lock();
			LOG.debug("Validated user auth token for '{}'", principal.getPrincipalId());
		}
		return principal;
	}

	protected SSOPrincipal validateAppTokenWithSecurityService(String authToken, String componentId)
			throws ForbiddenException {
		  Utils.checkState(checkServiceActiveIfInActive(), "Security service not active");
	    StringBuilder tokenValidationRequest = new StringBuilder();
			try {
				tokenValidationRequest.append(URLEncoder.encode("token", "UTF-8"))
					.append("=")
					.append(URLEncoder.encode(authToken, "UTF-8"));
				if (componentId != null) {
					tokenValidationRequest.append("&")
					.append(URLEncoder.encode("client_id", "UTF-8"))
					.append("=")
					.append(URLEncoder.encode(componentId, "UTF-8"));	
					if (clientSecret != null) {
						tokenValidationRequest.append("&")
						.append(URLEncoder.encode("client_secret", "UTF-8"))
						.append("=")
						.append(URLEncoder.encode(clientSecret, "UTF-8"));
					}
				}
				
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(
						Utils.format("Could not encode app token '{}', message: {}", authToken, e.getMessage())
						);
			}
			
			OIDCPrincipalJson principal;
	    try {
				RestClient restClient = getAppAuthClientBuilder().header("Content-Type", "application/x-www-form-urlencoded").build();
				RestClient.Response response = restClient.post(tokenValidationRequest);
	      if (response.getStatus() == HttpURLConnection.HTTP_OK) {
	        updateConnectionTimeout(response);
					principal = response.getData(OIDCPrincipalJson.class);
	      } else if (response.getStatus() == HttpURLConnection.HTTP_FORBIDDEN) {
	        throw new ForbiddenException(response.getError());
	      } else {
	        throw new RuntimeException(Utils.format(
	            "Could not validate app token for component ID '{}', HTTP status '{}' message: {}",
	            componentId,
	            response.getStatus(),
	            response.getError()
	        ));
	      }
	    } catch (IOException ex){
	      LOG.warn("Could not do app token validation, going inactive: {}", ex.toString());
	      serviceActive = false;
	      throw new RuntimeException(Utils.format("Could not connect to security service: {}", ex), ex);
	    }
	    if (principal != null) {
	      principal.setTokenStr(authToken);
	      principal.lock();
	      LOG.debug("Validated app auth token for '{}'", principal.getPrincipalId());
	    }
	    return principal;
	}

	@VisibleForTesting
	int getConnectionTimeout() {
		return connTimeout;
	}

}
