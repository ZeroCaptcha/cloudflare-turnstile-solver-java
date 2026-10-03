package io.zerocaptcha.turnstile;

/** The API refused a request, the task ended without a token, or the wait ran out. */
public final class ZeroCaptchaException extends Exception {
  private static final long serialVersionUID = 1L;

  private final String code;
  private final String requestId;

  /**
   * @param code the API's code, such as insufficient_funds or ERROR_CAPTCHA_UNSOLVABLE, or timeout
   * @param requestId what to quote when you ask support about the request; null when there is none
   */
  public ZeroCaptchaException(String code, String message, String requestId) {
    super(code + ": " + message);
    this.code = code;
    this.requestId = requestId;
  }

  public String code() {
    return code;
  }

  public String requestId() {
    return requestId;
  }
}
