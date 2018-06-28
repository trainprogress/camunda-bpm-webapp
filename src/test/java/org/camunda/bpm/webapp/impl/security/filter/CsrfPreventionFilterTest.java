package org.camunda.bpm.webapp.impl.security.filter;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.rule.PowerMockRule;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import static org.powermock.api.mockito.PowerMockito.when;

/**
 * @author Nikola Koevski
 */
@RunWith(Parameterized.class)
@PowerMockIgnore("javax.security.*")
public class CsrfPreventionFilterTest {

  protected static final String SERVICE_PATH = "/camunda";
  protected static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";
  protected static final String CSRF_HEADER_NAME = "X-XSRF-TOKEN";
  protected static final String CSRF_HEADER_REQUIRED = "Required";

  @Rule
  public PowerMockRule rule = new PowerMockRule();

  protected Filter csrfPreventionFilter;

  protected String nonModifyingRequestUrl;
  protected String modifyingRequestUrl;

  // flags a modifying request (POST/PUT/DELETE) as a non-modifying one
  protected boolean isModifyingFetchRequest;

  @Parameterized.Parameters
  public static Collection<Object[]> getRequestUrls() {
    return Arrays.asList(new Object[][]{
      {"/app/cockpit/default/", "/api/admin/auth/user/default/login/cockpit", true},
      {"/app/cockpit/engine1/", "/api/admin/auth/user/engine1/login/cockpit", true},

      {"/app/cockpit/default/", "/api/engine/engine/default/history/task/count", false},
      {"/app/cockpit/engine1/", "/api/engine/engine/engine1/history/task/count", false},

      {"/app/tasklist/default/", "/api/admin/auth/user/default/login/tasklist", true},
      {"/app/tasklist/engine1/", "/api/admin/auth/user/engine1/login/tasklist", true},

      {"/app/tasklist/default/", "api/engine/engine/default/task/task-id/submit-form", false},
      {"/app/tasklist/engine2/", "api/engine/engine/engine2/task/task-id/submit-form", false},

      {"/app/admin/default/", "/api/admin/auth/user/default/login/admin", true},
      {"/app/admin/engine1/", "/api/admin/auth/user/engine1/login/admin", true},

      {"/app/admin/default/", "api/admin/setup/default/user/create", false},
      {"/app/admin/engine3/", "api/admin/setup/engine3/user/create", false},

      {"/app/welcome/default/", "/api/admin/auth/user/default/login/welcome", true},
      {"/app/welcome/engine1/", "/api/admin/auth/user/engine1/login/welcome", true}
    });
  }

  public CsrfPreventionFilterTest(String nonModifyingRequestUrl, String modifyingRequestUrl, boolean isModifyingFetchRequest) {
    this.nonModifyingRequestUrl = nonModifyingRequestUrl;
    this.modifyingRequestUrl = modifyingRequestUrl;
    this.isModifyingFetchRequest = isModifyingFetchRequest;
  }

  @Before
  public void setup() throws ServletException {
    setupFilter();
  }

  protected void setupFilter() throws ServletException {
    MockFilterConfig config = new MockFilterConfig();
    csrfPreventionFilter = new CsrfPreventionFilter();
    csrfPreventionFilter.init(config);
  }

  protected void applyFilter(MockHttpServletRequest request, MockHttpServletResponse response) throws IOException, ServletException {
    FilterChain filterChain = new MockFilterChain();
    csrfPreventionFilter.doFilter(request, response, filterChain);
  }

  @Test
  public void testNonModifyingRequestTokenGeneration() throws IOException, ServletException {
    performNonModifyingRequest(nonModifyingRequestUrl);
  }

  @Test
  public void testConsecutiveNonModifyingRequestTokenGeneration() throws IOException, ServletException {
    // first non-modifying request
    String firstToken = performNonModifyingRequest(nonModifyingRequestUrl);
    // second non-modifying request
    String secondToken = performNonModifyingRequest(nonModifyingRequestUrl);

    Assert.assertNotEquals(firstToken, secondToken);
  }

  @Test
  public void testModifyingRequestTokenValidation() throws IOException, ServletException {
    // first non-modifying request
    String token = performNonModifyingRequest(nonModifyingRequestUrl);

    if (isModifyingFetchRequest) {
      String secondToken = performNonModifyingRequest(modifyingRequestUrl);
      Assert.assertNotEquals(token, secondToken);
    } else {
      HttpServletResponse response = performModifyingRequest(token);
      Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
    }
  }

  @Test
  public void testModifyingRequestInvalidToken() throws IOException, ServletException {
    String token = performNonModifyingRequest(nonModifyingRequestUrl);

    if (!isModifyingFetchRequest) {
      // invalid header token
      MockHttpServletResponse response = performModifyingRequest("invalid header token", token);
      Assert.assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
//      Assert.assertEquals(CSRF_HEADER_REQUIRED, (String) response.getHeader(CSRF_HEADER_NAME));

      // no header token
//      MockHttpServletRequest modifyingRequest = new MockHttpServletRequest();
//      modifyingRequest.setMethod("POST");
//      modifyingRequest.setRequestURI(SERVICE_PATH  + modifyingRequestUrl);
//      modifyingRequest.setContextPath(SERVICE_PATH);
//      Cookie[] cookies = {new Cookie(CSRF_COOKIE_NAME, token)};
//      modifyingRequest.setCookies(cookies);
//
//      applyFilter(modifyingRequest, response);
//      Assert.assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
//      Assert.assertEquals("", response.getErrorMessage());
//      Assert.assertEquals(CSRF_HEADER_REQUIRED, (String) response.getHeader(CSRF_HEADER_NAME));

      // invalid cookie token
      response = performModifyingRequest(token, "invalid cookie token");
      Assert.assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());

      // null cookie token
      response = performModifyingRequest(token, null);
      Assert.assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
    }
  }

  protected String performNonModifyingRequest(String requestUrl) throws IOException, ServletException {
    MockHttpServletResponse response = new MockHttpServletResponse();

    MockHttpServletRequest nonModifyingRequest = new MockHttpServletRequest();
    nonModifyingRequest.setMethod("GET");
    nonModifyingRequest.setRequestURI(SERVICE_PATH  + requestUrl);
    nonModifyingRequest.setContextPath(SERVICE_PATH);

    applyFilter(nonModifyingRequest, response);

    Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

    Cookie cookieToken = response.getCookie(CSRF_COOKIE_NAME);
    String headerToken = (String) response.getHeader(CSRF_HEADER_NAME);

    Assert.assertNotNull(cookieToken);
    Assert.assertNotNull(headerToken);
    Assert.assertEquals("No Cookie Token!",false, cookieToken.getValue().isEmpty());
    Assert.assertEquals("No HTTP Header Token!",false, headerToken.isEmpty());
    Assert.assertEquals("Cookie and HTTP Header Tokens do not match!", cookieToken.getValue(), headerToken);

    return headerToken;
  }

  protected MockHttpServletResponse performModifyingRequest(String token) throws IOException, ServletException {
    return performModifyingRequest(token, token);
  }

  protected MockHttpServletResponse performModifyingRequest(String headerToken, String cookieToken) throws IOException, ServletException {
    MockHttpServletResponse response = new MockHttpServletResponse();

    MockHttpServletRequest modifyingRequest = new MockHttpServletRequest();
    modifyingRequest.setMethod("POST");
    modifyingRequest.setRequestURI(SERVICE_PATH  + modifyingRequestUrl);
    modifyingRequest.setContextPath(SERVICE_PATH);

    modifyingRequest.addHeader(CSRF_HEADER_NAME, headerToken);
    Cookie[] cookies = {new Cookie(CSRF_COOKIE_NAME, cookieToken)};
    modifyingRequest.setCookies(cookies);

    applyFilter(modifyingRequest, response);

    return response;
  }
}
