/**
 * Copyright 2014 Telefonica Investigación y Desarrollo, S.A.U <br>
 * This file is part of FI-WARE project.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License.
 * </p>
 * <p>
 * You may obtain a copy of the License at:<br>
 * <br>
 * http://www.apache.org/licenses/LICENSE-2.0
 * </p>
 * <p>
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * </p>
 * <p>
 * See the License for the specific language governing permissions and limitations under the License.
 * </p>
 * <p>
 * For those usages not covered by the Apache version 2.0 License please contact with opensource@tid.es
 * </p>
 */

package com.telefonica.euro_iaas.paasmanager.rest.auth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.GenericFilterBean;

import com.telefonica.euro_iaas.paasmanager.model.dto.PaasManagerUser;
import com.telefonica.euro_iaas.paasmanager.util.SystemPropertiesProvider;

/**
 * The Class OpenStackAuthenticationFilter.
 * 
 * @author fernandolopezaguilar
 */
public class OpenStackAuthenticationFilter extends GenericFilterBean {

    private static Logger logger = LoggerFactory.getLogger(OpenStackAuthenticationFilter.class);

    /**
     * The authentication details source.
     */
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    /**
     * The ignore failure.
     */
    private boolean ignoreFailure = false;
    /**
     * The authentication manager.
     */
    private AuthenticationManager authenticationManager;
    /**
     * The authentication entry point.
     */
    private AuthenticationEntryPoint authenticationEntryPoint;
    /**
     * The remember me services.
     */
    private RememberMeServices rememberMeServices = new NullRememberMeServices();
    /**
     * The Constant OPENSTACK_IDENTIFIER.
     */
    public static final String OPENSTACK_IDENTIFIER = "openstack";
    /**
     * The Constant OPENSTACK_HEADER_TOKEN.
     */
    public static final String OPENSTACK_HEADER_TOKEN = "X-Auth-Token";
    /**
     * The Constant OPENSTACK_HEADER_TOKEN.
     */
    public static final String OPENSTACK_HEADER_TENANTID = "Tenant-ID";
    /**
     * The system properties provider.
     */
    private SystemPropertiesProvider systemPropertiesProvider;

    /**
     * Instantiates a new open stack authentication filter.
     */
    protected OpenStackAuthenticationFilter() {
    }

    /**
     * Creates an instance which will authenticate against the supplied.
     * 
     * @param pAuthenticationManager
     *            the bean to submit authentication requests to
     *            {@code AuthenticationManager} and which will ignore failed
     *            authentication attempts, allowing the request to proceed down
     *            the filter chain.
     */
    public OpenStackAuthenticationFilter(final AuthenticationManager pAuthenticationManager) {
        this.authenticationManager = pAuthenticationManager;
        ignoreFailure = true;
    }

    /**
     * Creates an instance which will authenticate against the supplied.
     * 
     * @param pAuthenticationManager
     *            the bean to submit authentication requests to
     * @param pAuthenticationEntryPoint
     *            will be invoked when authentication fails.
     */
    public OpenStackAuthenticationFilter(final AuthenticationManager pAuthenticationManager,
            final AuthenticationEntryPoint pAuthenticationEntryPoint) {
        this.authenticationManager = pAuthenticationManager;
        this.authenticationEntryPoint = pAuthenticationEntryPoint;
    }

    /**
     * (non-Javadoc) @see
     * javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
     * javax.servlet.ServletResponse, javax.servlet.FilterChain).
     */
    public final void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
            throws IOException, ServletException {

        final boolean debug = logger.isDebugEnabled();

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        String header = request.getHeader(OPENSTACK_HEADER_TOKEN);
        String pathInfo = request.getPathInfo();
        logger.debug(header);
        logger.debug(pathInfo);


        MDC.put("txId", ((HttpServletRequest) req).getSession().getId());

        if (pathInfo != null && (pathInfo.equals("/") || pathInfo.equals("/extensions"))) {
            /**
             * It is not needed to authenticate these operations
             */
            logger.debug("Operation does not need to Authenticate");
        } else {

            if (header == null) {
                header = "";
            }

            try {
                String token = header;
                if ("".equals(token)) {
                    String str = "Missing token header";
                    logger.info(str);
                    throw new BadCredentialsException(str);
                }
                String tenantId = request.getHeader(OPENSTACK_HEADER_TENANTID);
                logger.debug(tenantId);
                logger.debug(token);
                // String tenantId = request.getPathInfo().split("/")[3];

                if (debug) {
                    logger.debug("OpenStack Authentication Authorization header " + "found for user '" + token
                            + "' and tenant " + tenantId);
                }

                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(token,
                        tenantId);
                authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
                Authentication authResult = authenticationManager.authenticate(authRequest);

                if (debug) {
                    logger.debug("Authentication success: " + authResult);
                }

                // check AUTH-TOKEN and VDC are the same
                String uri = request.getRequestURI();
                logger.debug("URI: " + uri);
                if (uri.contains("vdc") && !uri.contains(tenantId)) {
                    String str = "Bad credentials for requested VDC";
                    logger.info(str);
                    throw new AccessDeniedException(str);
                }

                PaasManagerUser user = (PaasManagerUser) authResult.getPrincipal();

                logger.debug("User: " + user.getUsername());
                logger.debug("Token: " + user.getToken());
                logger.debug("Tenant: " + user.getTenantId());
                logger.debug("TenantName - Org: " + user.getTenantName());

                SecurityContextHolder.getContext().setAuthentication(authResult);
                // SecurityContextHolder.setStrategyName("MODE_INHERITABLETHREADLOCAL");

                rememberMeServices.loginSuccess(request, response, authResult);

                onSuccessfulAuthentication(request, response, authResult);

            } catch (AuthenticationException failed) {
                SecurityContextHolder.clearContext();

                if (debug) {
                    logger.debug("Authentication request for failed: " + failed);
                }

                rememberMeServices.loginFail(request, response);
                onUnsuccessfulAuthentication(request, response, failed);

                if (ignoreFailure) {
                    chain.doFilter(request, response);
                } else {
                    authenticationEntryPoint.commence(request, response, failed);
                }

                return;
            }catch (AccessDeniedException ex){
                throw ex;
            } catch (Exception ex) {
                SecurityContextHolder.clearContext();

                if (debug) {
                    logger.debug("Authentication exception: " + ex);
                }

                rememberMeServices.loginFail(request, response);

                if (ignoreFailure) {
                    chain.doFilter(request, response);
                } else {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                }
                return;
            }

            String keystoneURL = systemPropertiesProvider.getProperty(SystemPropertiesProvider.KEYSTONE_URL);

            response.addHeader("Www-Authenticate", "Keystone uri='" + keystoneURL + "'");
        }

        // TODO jesuspg: question:add APIException
        chain.doFilter(request, response);

    }

    /**
     * On successful authentication.
     * 
     * @param request
     *            the request
     * @param response
     *            the response
     * @param authResult
     *            the auth result
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    protected void onSuccessfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authResult) throws IOException {
    }

    /**
     * On unsuccessful authentication.
     * 
     * @param request
     *            the request
     * @param response
     *            the response
     * @param failed
     *            the failed
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    protected void onUnsuccessfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException failed) throws IOException {
    }

    /**
     * Gets the authentication details source.
     * 
     * @return the authentication details source
     */
    public final AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }

    /**
     * Sets the authentication details source.
     * 
     * @param pAuthenticationDetailsSource
     *            the authentication details source
     */
    public final void setAuthenticationDetailsSource(
            final AuthenticationDetailsSource<HttpServletRequest, ?> pAuthenticationDetailsSource) {
        this.authenticationDetailsSource = pAuthenticationDetailsSource;
    }

    /**
     * Checks if is ignore failure.
     * 
     * @return true, if is ignore failure
     */
    public final boolean isIgnoreFailure() {
        return ignoreFailure;
    }

    /**
     * Sets the ignore failure.
     * 
     * @param pIgnoreFailure
     *            the new ignore failure
     */
    public final void setIgnoreFailure(final boolean pIgnoreFailure) {
        this.ignoreFailure = pIgnoreFailure;
    }

    /**
     * Gets the authentication manager.
     * 
     * @return the authentication manager
     */
    public final AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    /**
     * Sets the authentication manager.
     * 
     * @param pAuthenticationEntryPoint
     *            the new authentication manager
     */
    public final void setAuthenticationManager(final AuthenticationManager pAuthenticationEntryPoint) {
        this.authenticationManager = pAuthenticationEntryPoint;
    }

    /**
     * Gets the authentication entry point.
     * 
     * @return the authentication entry point
     */
    public final AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    /**
     * Sets the authentication entry point.
     * 
     * @param pAuthenticationEntryPoint
     *            the new authentication entry point
     */
    public final void setAuthenticationEntryPoint(final AuthenticationEntryPoint pAuthenticationEntryPoint) {
        this.authenticationEntryPoint = pAuthenticationEntryPoint;
    }

    /**
     * Gets the remember me services.
     * 
     * @return the remember me services
     */
    public final RememberMeServices getRememberMeServices() {
        return rememberMeServices;
    }

    /**
     * Sets the remember me services.
     * 
     * @param pRememberMeServices
     *            the new remember me services
     */
    public final void setRememberMeServices(final RememberMeServices pRememberMeServices) {
        this.rememberMeServices = pRememberMeServices;
    }

    /*
     * @Override public Authentication attemptAuthentication(HttpServletRequest
     * request, HttpServletResponse response) throws AuthenticationException,
     * IOException, ServletException { final String username =
     * OPENSTACK_IDENTIFIER; String token =
     * request.getHeader(OPENSTACK_HEADER_TOKEN); if (token == null) {
     * logger.debug("Failed to obtain an artifact (openstack
     * tocken)"); token = ""; } UsernamePasswordAuthenticationToken authRequest
     * = new UsernamePasswordAuthenticationToken(username, token);
     * authRequest.setDetails
     * (authenticationDetailsSource.buildDetails(request)); Authentication
     * authResult = getAuthenticationManager().authenticate(authRequest);
     * SecurityContextHolder.getContext().setAuthentication(authResult); return
     * authResult; }
     * 
     * @Override protected boolean requiresAuthentication(HttpServletRequest
     * request, HttpServletResponse response) { return true; }
     */
    /**
     * Gets the system properties provider.
     * 
     * @return the systemPropertiesProvider
     */
    public final SystemPropertiesProvider getSystemPropertiesProvider() {
        return systemPropertiesProvider;
    }

    /**
     * Sets the system properties provider.
     * 
     * @param pSystemPropertiesProvider
     *            the systemPropertiesProvider to set
     */
    public final void setSystemPropertiesProvider(final SystemPropertiesProvider pSystemPropertiesProvider) {
        this.systemPropertiesProvider = pSystemPropertiesProvider;
    }
}
