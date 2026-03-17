/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.apimgt.gateway.handlers.streaming.websocket;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.netty.channel.ChannelHandlerContext;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.apimgt.api.gateway.GraphQLSchemaDTO;
import org.wso2.carbon.apimgt.gateway.inbound.InboundMessageContext;
import org.wso2.carbon.apimgt.gateway.inbound.websocket.Authentication.ApiKeyAuthenticator;
import org.wso2.carbon.apimgt.gateway.inbound.websocket.Authentication.NoAuthAuthenticator;
import org.wso2.carbon.apimgt.gateway.inbound.websocket.Authentication.OAuthAuthenticator;
import org.wso2.carbon.apimgt.impl.dto.ResourceInfoDTO;
import org.wso2.carbon.apimgt.impl.jwt.SignedJWTInfo;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Lightweight TTL cache used to keep websocket connection metadata that can be re-hydrated per frame.
 */
public class StatelessContextManager {

    private static final String CACHE_TTL_SECONDS_PROPERTY = "apim.websocket.nano.context.ttl.seconds";
    private static final long DEFAULT_CACHE_TTL_SECONDS = 900L;
    private static final StatelessContextManager INSTANCE = new StatelessContextManager();
    private final Cache<String, ConnectionContextSnapshot> connectionContextCache;

    private StatelessContextManager() {
        this.connectionContextCache = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofSeconds(getCacheTtlSeconds()))
                .maximumSize(1_000_000)
                .build();
    }

    public static StatelessContextManager getInstance() {
        return INSTANCE;
    }

    public void putContext(String connectionId, InboundMessageContext inboundMessageContext) {
        if (connectionId == null || inboundMessageContext == null) {
            return;
        }
        connectionContextCache.put(connectionId, ConnectionContextSnapshot.fromContext(inboundMessageContext));
    }

    public InboundMessageContext getContext(String connectionId, ChannelHandlerContext channelHandlerContext, String userIP) {
        ConnectionContextSnapshot snapshot = connectionContextCache.getIfPresent(connectionId);
        if (snapshot == null) {
            return null;
        }
        return snapshot.toContext(channelHandlerContext, userIP);
    }

    public void invalidate(String connectionId) {
        if (connectionId != null) {
            connectionContextCache.invalidate(connectionId);
        }
    }

    private long getCacheTtlSeconds() {
        String configuredTtl = System.getProperty(CACHE_TTL_SECONDS_PROPERTY);
        if (configuredTtl == null) {
            return DEFAULT_CACHE_TTL_SECONDS;
        }
        try {
            long parsed = Long.parseLong(configuredTtl);
            return parsed > 0 ? parsed : DEFAULT_CACHE_TTL_SECONDS;
        } catch (NumberFormatException ignore) {
            return DEFAULT_CACHE_TTL_SECONDS;
        }
    }

    /**
     * Snapshot persisted in Caffeine cache to avoid retaining full processing graph in channel attributes.
     */
    private static final class ConnectionContextSnapshot {

        private String tenantDomain;
        private String fullRequestPath;
        private String requestPath;
        private String version;
        private String token;
        private String apiContext;
        private String apiName;
        private String keyType;
        private org.apache.synapse.api.API api;
        private String electedRoute;
        private org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext authContext;
        private org.wso2.carbon.apimgt.keymgt.model.entity.API electedAPI;
        private SignedJWTInfo signedJWTInfo;
        private Map<String, ResourceInfoDTO> resourcesMap;
        private String matchingResource;
        private boolean jwtToken;
        private String authenticatorClassName;
        private GraphQLSchemaDTO graphQLSchemaDTO;
        private Map<String, String> requestHeaders;

        private static ConnectionContextSnapshot fromContext(InboundMessageContext inboundMessageContext) {
            ConnectionContextSnapshot snapshot = new ConnectionContextSnapshot();
            snapshot.tenantDomain = inboundMessageContext.getTenantDomain();
            snapshot.fullRequestPath = inboundMessageContext.getFullRequestPath();
            snapshot.requestPath = inboundMessageContext.getRequestPath();
            snapshot.version = inboundMessageContext.getVersion();
            snapshot.token = inboundMessageContext.getToken();
            snapshot.apiContext = inboundMessageContext.getApiContext();
            snapshot.apiName = inboundMessageContext.getApiName();
            snapshot.keyType = inboundMessageContext.getKeyType();
            snapshot.api = inboundMessageContext.getApi();
            snapshot.electedRoute = inboundMessageContext.getElectedRoute();
            snapshot.authContext = inboundMessageContext.getAuthContext();
            snapshot.electedAPI = inboundMessageContext.getElectedAPI();
            snapshot.signedJWTInfo = inboundMessageContext.getSignedJWTInfo();
            snapshot.resourcesMap = new HashMap<>(inboundMessageContext.getResourcesMap());
            snapshot.matchingResource = inboundMessageContext.getMatchingResource();
            snapshot.jwtToken = inboundMessageContext.isJWTToken();
            snapshot.graphQLSchemaDTO = inboundMessageContext.getGraphQLSchemaDTO();
            snapshot.requestHeaders = new HashMap<>(inboundMessageContext.getRequestHeaders());
            if (inboundMessageContext.getAuthenticator() != null) {
                snapshot.authenticatorClassName = inboundMessageContext.getAuthenticator().getClass().getName();
            }

            return snapshot;
        }

        private InboundMessageContext toContext(ChannelHandlerContext channelHandlerContext, String userIP) {
            InboundMessageContext inboundMessageContext = new InboundMessageContext();
            inboundMessageContext.setTenantDomain(tenantDomain);
            inboundMessageContext.setFullRequestPath(fullRequestPath);
            inboundMessageContext.setRequestPath(requestPath);
            inboundMessageContext.setVersion(version);
            inboundMessageContext.setToken(token);
            inboundMessageContext.setApiContext(apiContext);
            inboundMessageContext.setApiName(apiName);
            inboundMessageContext.setKeyType(keyType);
            inboundMessageContext.setApi(api);
            inboundMessageContext.setElectedRoute(electedRoute);
            inboundMessageContext.setAuthContext(authContext);
            inboundMessageContext.setElectedAPI(electedAPI);
            inboundMessageContext.setSignedJWTInfo(signedJWTInfo);
            inboundMessageContext.getResourcesMap().putAll(resourcesMap);
            inboundMessageContext.setMatchingResource(matchingResource);
            inboundMessageContext.setJWTToken(jwtToken);
            inboundMessageContext.setGraphQLSchemaDTO(graphQLSchemaDTO);
            inboundMessageContext.setCtx(channelHandlerContext);
            inboundMessageContext.setUserIP(userIP);
            inboundMessageContext.getRequestHeaders().putAll(requestHeaders);

            if (token != null && !token.isEmpty()) {
                inboundMessageContext.getRequestHeaders().put(HttpHeaders.AUTHORIZATION, "Bearer " + token);
            }

            setAuthenticator(inboundMessageContext);
            return inboundMessageContext;
        }

        private void setAuthenticator(InboundMessageContext inboundMessageContext) {
            if (OAuthAuthenticator.class.getName().equals(authenticatorClassName)) {
                inboundMessageContext.setAuthenticator(new OAuthAuthenticator());
            } else if (ApiKeyAuthenticator.class.getName().equals(authenticatorClassName)) {
                inboundMessageContext.setAuthenticator(new ApiKeyAuthenticator());
            } else if (NoAuthAuthenticator.class.getName().equals(authenticatorClassName)) {
                inboundMessageContext.setAuthenticator(new NoAuthAuthenticator());
            }
        }
    }
}
