/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.camunda.bpm.webapp.impl.security.filter;

import org.camunda.bpm.webapp.impl.security.filter.util.CsrfConstants;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Provides basic CSRF protection. The filter assumes that the
 * client side has adapted the transfer of the nonce through the 'X-CSRF-Token'
 * header.
 *
 * <pre>
 * Positive scenario:
 *           Client                            Server
 *              |                                 |
 *              | GET Fetch Request              \| JSESSIONID
 *              |---------------------------------| X-CSRF-Token
 *              |                                /| pair generation
 *              |/Response to Fetch Request       |
 *              |---------------------------------|
 * JSESSIONID   |\                                |
 * X-CSRF-Token |                                 |
 * pair cached  | POST Request with valid nonce  \| JSESSIONID
 *              |---------------------------------| X-CSRF-Token
 *              |                                /| pair validation
 *              |/ Response to POST Request       |
 *              |---------------------------------|
 *              |\                                |
 *
 * Negative scenario:
 *           Client                            Server
 *              |                                 |
 *              | POST Request without nonce     \| JSESSIONID
 *              |---------------------------------| X-CSRF-Token
 *              |                                /| pair validation
 *              |/Request is rejected             |
 *              |---------------------------------|
 *              |\                                |
 *
 *           Client                            Server
 *              |                                 |
 *              | POST Request with invalid nonce\| JSESSIONID
 *              |---------------------------------| X-CSRF-Token
 *              |                                /| pair validation
 *              |/Request is rejected             |
 *              |---------------------------------|
 *              |\                                |
 * </pre>
 *
 * <i>Parts of this code were ported from the <code>CsrfPreventionFilter</code> class
 * of Apache Tomcat. Furthermore, the <code>RestCsrfPreventionFilter</code> class from
 * the same codebase was used as a guideline.</i>
 *
 * @author Nikola Koevski
 */
public class CsrfPreventionFilter extends BaseCsrfPreventionFilter {

  protected static final Pattern NON_MODIFYING_METHODS_PATTERN = Pattern.compile("GET|HEAD|OPTIONS");

  private final Set<String> entryPoints = new HashSet<String>();
  private final Set<String> pathsAcceptingParams = new HashSet<String>();

  private int nonceCacheSize = 5;

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    boolean isFetchRequest = isNonModifyingRequest(request);
    boolean isTokenValid = false;

    if (!isFetchRequest) {
      // Not a fetch request -> validate token
      isTokenValid = doTokenValidation(request, response);
    }

    if ((isFetchRequest && isValidFetchRequest(request)) /*|| isTokenValid*/){
      // Fetch request OR valid token -> provide new token
      fetchNewToken(request, response);
    }

    filterChain.doFilter(request, response);
  }

  // Validate request token value with session token values
  protected boolean doTokenValidation(HttpServletRequest request, HttpServletResponse response) throws IOException {
    HttpSession session = request.getSession(false);

//    LRUCache<String> lruNonceCache = (session != null)?
//      (LRUCache<String>) session.getAttribute(CsrfConstants.CSRF_NONCE_SESSION_ATTR_NAME) : null;
    String sessionNonce = (session != null)?
      (String) session.getAttribute(CsrfConstants.CSRF_NONCE_SESSION_ATTR_NAME) : null;
    String requestNonce = retrieveRequestToken(request);

//    if (lruNonceCache == null || requestNonce == null || !lruNonceCache.contains(requestNonce)) {
    if (sessionNonce == null || requestNonce == null || !sessionNonce.equals(requestNonce)) {
      response.addHeader(CsrfConstants.CSRF_NONCE_HEADER_NAME, CsrfConstants.CSRF_NONCE_HEADER_REQUIRED_VALUE);
      response.sendError(getDenyStatus(), "Request contains an incorrect CSRF token.");

      return false;
    }

    return true;
  }

  // The Token can be sent through the Request Header, or if not possible,
  // as a Request Parameter. Note that the Requesting URL needs to be declared
  // in the `pathsAcceptingParams` parameter in the web.xml then.
  protected String retrieveRequestToken(HttpServletRequest request) {
    String token = request.getHeader(CsrfConstants.CSRF_NONCE_HEADER_NAME);

    if ((token == null || token.isEmpty())
      && pathsAcceptingParams.contains(getRequestedPath(request))) {

      String[] params = request.getParameterValues(CsrfConstants.CSRF_NONCE_REQUEST_PARAM);
      if (params != null && params.length > 0) {
        String nonce = params[0];
        for (String param : params) {
          if (!nonce.equals(param)) {
            return null;
          }
        }
        return nonce;
      }
    }

    return token;
  }

  // If the Request carries a valid token, or it is a Fetch request,
  // a new Token needs to be provided with the response.
  protected void fetchNewToken(HttpServletRequest request, HttpServletResponse response) {
    String newNonce = generateNonce();
    HttpSession session = request.getSession(true);

//    LRUCache<String> lruNonceCache = (session.getAttribute(CsrfConstants.CSRF_NONCE_SESSION_ATTR_NAME) != null)?
//      (LRUCache<String>) session.getAttribute(CsrfConstants.CSRF_NONCE_SESSION_ATTR_NAME) : new LRUCache<String>(this.nonceCacheSize);
//
//    lruNonceCache.add(newNonce);
//    session.setAttribute(CsrfConstants.CSRF_NONCE_SESSION_ATTR_NAME, lruNonceCache);
//    response.setHeader(CsrfConstants.CSRF_NONCE_COOKIE_NAME, newNonce);
    session.setAttribute(CsrfConstants.CSRF_NONCE_SESSION_ATTR_NAME, newNonce);
    Cookie csrfCookie = new Cookie(CsrfConstants.CSRF_NONCE_COOKIE_NAME, newNonce);
    csrfCookie.setPath("/camunda");
    response.addCookie(csrfCookie);
  }

  // Check if no token has been generated already,
  // or if it's explicitly requested to be generated
  protected boolean isValidFetchRequest(HttpServletRequest request) {
    return request.getSession(false).getAttribute(CsrfConstants.CSRF_NONCE_SESSION_ATTR_NAME) == null
      || CsrfConstants.CSRF_NONCE_HEADER_FETCH_VALUE.equals(request.getHeader(CsrfConstants.CSRF_NONCE_HEADER_NAME));
  }

  // A non-modifying request is one that is either a 'HTTP GET' request,
  // or is allowed explicitly through the 'entryPoints' parameter in the web.xml
  protected boolean isNonModifyingRequest(HttpServletRequest request) {
    return NON_MODIFYING_METHODS_PATTERN.matcher(request.getMethod()).matches()
        || entryPoints.contains(getRequestedPath(request));
  }

  /**
   * Entry points are URLs that will not be tested for the presence of a valid
   * nonce. They are used to provide a way to navigate back to a protected
   * application after navigating away from it. Entry points will be limited
   * to HTTP GET requests and should not trigger any security sensitive
   * actions.
   *
   * @param entryPoints   Comma separated list of URLs to be configured as
   *                      entry points.
   */
  public void setEntryPoints(String entryPoints) {
    this.entryPoints.addAll(parseURLs(entryPoints));
  }

  /**
   * A comma separated list of URLs that can accept nonces via request
   * parameter 'X-CSRF-Token'. For use cases when a nonce information cannot
   * be provided via header, one can provide it via request parameters. If
   * there is a X-CSRF-Token header, it will be taken with preference over any
   * parameter with the same name in the request. Request parameters cannot be
   * used to fetch new nonce, only header.
   *
   * @param pathsList
   *            Comma separated list of URLs to be configured as paths
   *            accepting request parameters with nonce information.
   */
  public void setPathsAcceptingParams(String pathsList) {
    this.pathsAcceptingParams.addAll(parseURLs(pathsList));
  }

  public Set<String> getPathsAcceptingParams() {
    return pathsAcceptingParams;
  }

  private Set<String> parseURLs(String urlString) {
    Set<String> urlSet = new HashSet<String>();

    if (urlString != null && !urlString.isEmpty()) {
      String values[] = urlString.split(",");
      for (String value : values) {
        urlSet.add(value.trim());
      }
    }

    return urlSet;
  }

  private String getRequestedPath(HttpServletRequest request) {
    String path = request.getServletPath();

    if (request.getPathInfo() != null) {
      path = path + request.getPathInfo();
    }

    return path;
  }

  /**
   * Sets the number of previously issued nonces that will be cached on a LRU
   * basis to support parallel requests, limited use of the refresh and back
   * in the browser and similar behaviors that may result in the submission
   * of a previous nonce rather than the current one. If not set, the default
   * value of 5 will be used.
   *
   * @param nonceCacheSize    The number of nonces to cache
   */
  public void setNonceCacheSize(int nonceCacheSize) {
    this.nonceCacheSize = nonceCacheSize;
  }

  protected static class LRUCache<T> implements Serializable {

    private static final long serialVersionUID = 1L;

    // Although the internal implementation uses a Map, this cache
    // implementation is only concerned with the keys.
    private final Map<T,T> cache;

    public LRUCache(final int cacheSize) {
      cache = new LinkedHashMap<T,T>() {

        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<T,T> eldest) {
          return size() > cacheSize;
        }
      };
    }

    public void add(T key) {
      synchronized (cache) {
        cache.put(key, null);
      }
    }

    public boolean contains(T key) {
      synchronized (cache) {
        return cache.containsKey(key);
      }
    }
  }
}
