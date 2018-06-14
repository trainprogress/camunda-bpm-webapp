package org.camunda.bpm.webapp.impl.security.filter.util;

/**
 * @author Nikola Koevski
 */
public final class CsrfConstants {

  public static final String CSRF_NONCE_SESSION_ATTR_NAME = "CAMUNDA_CSRF_NONCE";

  public static final String CSRF_NONCE_REQUEST_PARAM = "CSRF_NONCE";

  public static final String CSRF_NONCE_HEADER_NAME = "X-XSRF-TOKEN";

  public static final String CSRF_NONCE_COOKIE_NAME = "XSRF-TOKEN";

  public static final String CSRF_NONCE_HEADER_FETCH_VALUE = "Fetch";

  public static final String CSRF_NONCE_HEADER_REQUIRED_VALUE = "Required";

}
