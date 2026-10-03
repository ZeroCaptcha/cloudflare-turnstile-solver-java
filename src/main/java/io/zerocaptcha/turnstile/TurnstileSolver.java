package io.zerocaptcha.turnstile;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Solves Cloudflare Turnstile widgets with the ZeroCaptcha REST API: give it a page's URL and its
 * sitekey, and it returns a token to submit as the browser would. Uses java.net.http and Gson.
 */
public final class TurnstileSolver {

  /**
   * What to solve: the page the widget is on and its sitekey; the widget's action and cData if it
   * sets them; and your proxy, such as {@code http://user:pass@proxy.example.net:8080}, to solve
   * through it. Leave the optional ones null.
   */
  public record Task(String websiteUrl, String websiteKey, String action, String cdata, String proxy) {
    public Task(String websiteUrl, String websiteKey) {
      this(websiteUrl, websiteKey, null, null, null);
    }
  }

  /** Answers worth another try after a wait: too many requests, or a server busy or away. */
  private static final Set<Integer> RETRYABLE = Set.of(429, 502, 503, 504);

  private static final int ATTEMPTS = 3;
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

  private final HttpClient http;
  private final String api;
  private final String key;
  private final Duration interval;

  /** A solver with your API key (zc_live_…) for the API at {@code api}, asking every 2 seconds. */
  public TurnstileSolver(String api, String key) {
    this(api, key, Duration.ofSeconds(2));
  }

  public TurnstileSolver(String api, String key, Duration interval) {
    this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    this.api = api.replaceAll("/+$", "");
    this.key = key;
    this.interval = interval;
  }

  /**
   * Creates a Cloudflare Turnstile task, waits for it, and returns the token. The token works
   * once, for 300 seconds. A task that fails or expires throws {@link ZeroCaptchaException} with
   * its errorCode, and nothing is charged.
   */
  public String solve(Task task, Duration timeout) throws ZeroCaptchaException, InterruptedException {
    Instant deadline = Instant.now().plus(timeout);
    JsonObject body = new JsonObject();
    body.addProperty("type", task.proxy() == null ? "TurnstileTaskProxyless" : "TurnstileTask");
    body.addProperty("websiteURL", task.websiteUrl());
    body.addProperty("websiteKey", task.websiteKey());
    if (task.action() != null) {
      body.addProperty("action", task.action());
    }
    if (task.cdata() != null) {
      body.addProperty("cdata", task.cdata());
    }
    if (task.proxy() != null) {
      body.addProperty("proxy", task.proxy());
    }
    // One key per task: a retry after a lost reply returns this task instead of making another.
    String idempotencyKey = UUID.randomUUID().toString();
    JsonObject current = request("POST", "/v1/tasks", deadline, body, idempotencyKey);
    String status = text(current, "status");
    while ("queued".equals(status) || "running".equals(status)) {
      if (Instant.now().plus(interval).isAfter(deadline)) {
        throw new ZeroCaptchaException(
            "timeout", "Task " + text(current, "id") + " was still " + status + ".", null);
      }
      Thread.sleep(interval.toMillis());
      current = request("GET", "/v1/tasks/" + text(current, "id"), deadline, null, null);
      status = text(current, "status");
    }
    JsonElement solution = current.get("solution");
    String token =
        solution != null && solution.isJsonObject() ? text(solution.getAsJsonObject(), "token") : null;
    if ("succeeded".equals(status) && token != null && !token.isEmpty()) {
      return token;
    }
    String code = text(current, "errorCode");
    String description = text(current, "errorDescription");
    throw new ZeroCaptchaException(
        code != null ? code : String.valueOf(status),
        description != null ? description : "The task " + status + "; nothing was charged.",
        null);
  }

  /** Sends one request, trying it up to three times with the same Idempotency-Key. */
  private JsonObject request(
      String method, String path, Instant deadline, JsonObject body, String idempotencyKey)
      throws ZeroCaptchaException, InterruptedException {
    for (int attempt = 1; ; attempt++) {
      Duration left = Duration.between(Instant.now(), deadline);
      if (left.isNegative() || left.isZero()) {
        throw new ZeroCaptchaException("timeout", method + " " + path + " ran past the deadline.", null);
      }
      HttpRequest.Builder builder =
          HttpRequest.newBuilder(URI.create(api + path))
              .timeout(left.compareTo(REQUEST_TIMEOUT) < 0 ? left : REQUEST_TIMEOUT)
              .header("Authorization", "Bearer " + key)
              .header("Accept", "application/json");
      if (body != null) {
        builder
            .header("Content-Type", "application/json")
            .method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
      } else {
        builder.method(method, HttpRequest.BodyPublishers.noBody());
      }
      if (idempotencyKey != null) {
        builder.header("Idempotency-Key", idempotencyKey);
      }
      Duration wait = Duration.ofSeconds(attempt);
      ZeroCaptchaException failure;
      try {
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
          return JsonParser.parseString(response.body()).getAsJsonObject();
        }
        failure = problem(response);
        boolean retryable =
            RETRYABLE.contains(status)
                || (status == 409 && "idempotency_key_in_use".equals(failure.code()));
        if (!retryable) {
          throw failure;
        }
        String asked = response.headers().firstValue("retry-after").orElse("").trim();
        if (asked.matches("\\d+")) {
          wait = Duration.ofSeconds(Long.parseLong(asked));
        }
      } catch (IOException | JsonParseException | IllegalStateException error) {
        // No answer, or one cut short: the same Idempotency-Key makes a retry safe.
        failure = new ZeroCaptchaException("network", String.valueOf(error.getMessage()), null);
      }
      if (attempt >= ATTEMPTS) {
        throw failure;
      }
      if (Instant.now().plus(wait).isAfter(deadline)) {
        throw new ZeroCaptchaException("timeout", method + " " + path + " ran past the deadline.", null);
      }
      Thread.sleep(wait.toMillis());
    }
  }

  /** The API's problem document (RFC 9457) as an exception: its code, detail and request ID. */
  private static ZeroCaptchaException problem(HttpResponse<String> response) {
    JsonObject fields = new JsonObject();
    try {
      JsonElement parsed = JsonParser.parseString(response.body());
      if (parsed.isJsonObject()) {
        fields = parsed.getAsJsonObject();
      }
    } catch (JsonParseException error) {
      // Not a problem document, such as a proxy's HTML page.
    }
    String code = text(fields, "code");
    String detail = text(fields, "detail");
    String title = text(fields, "title");
    String requestId = text(fields, "request_id");
    return new ZeroCaptchaException(
        code != null ? code : "http_" + response.statusCode(),
        detail != null ? detail : title != null ? title : "HTTP " + response.statusCode(),
        requestId != null ? requestId : response.headers().firstValue("x-request-id").orElse(null));
  }

  /** A field's text, or null when it is missing or not text. */
  private static String text(JsonObject object, String name) {
    JsonElement value = object.get(name);
    return value != null && value.isJsonPrimitive() ? value.getAsString() : null;
  }
}
