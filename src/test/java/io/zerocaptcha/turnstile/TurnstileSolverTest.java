package io.zerocaptcha.turnstile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonObject;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** The solver against a stand-in API: no key, no real task, nothing spent. */
class TurnstileSolverTest {
  private static final String PAGE = "https://shop.example.com/login";
  private static final String SITEKEY = "0x4AAAAAAAB1cD2eF3gH4iJ5";
  private static final Duration TIMEOUT = Duration.ofSeconds(30);

  private static TurnstileSolver solver(StandInApi api) {
    return new TurnstileSolver(api.url(), StandInApi.KEY, Duration.ofMillis(10));
  }

  @Test
  void returnsTheTokenAndSendsTheTaskAsTheApiExpects() throws Exception {
    try (StandInApi api = new StandInApi("success")) {
      String token =
          solver(api).solve(new TurnstileSolver.Task(PAGE, SITEKEY, "login", "session-7f3a9c2e", null), TIMEOUT);
      assertEquals(StandInApi.TOKEN, token);
      StandInApi.Recorded create = api.requests.get(0);
      assertEquals("POST", create.method());
      assertEquals("/v1/tasks", create.path());
      assertEquals("Bearer " + StandInApi.KEY, create.authorization());
      assertNotNull(create.idempotencyKey());
      JsonObject expected = new JsonObject();
      expected.addProperty("type", "TurnstileTaskProxyless");
      expected.addProperty("websiteURL", PAGE);
      expected.addProperty("websiteKey", SITEKEY);
      // The widget's action and cData reach the API, so a site that checks them accepts the token.
      expected.addProperty("action", "login");
      expected.addProperty("cdata", "session-7f3a9c2e");
      assertEquals(expected, create.body());
      assertEquals(3, api.requests.size());
    }
  }

  @Test
  void aProxyMakesAProxiedTask() throws Exception {
    String proxy = "http://user:pass@proxy.example.net:8080";
    try (StandInApi api = new StandInApi("success")) {
      solver(api).solve(new TurnstileSolver.Task(PAGE, SITEKEY, null, null, proxy), TIMEOUT);
      JsonObject body = api.requests.get(0).body();
      assertEquals("TurnstileTask", body.get("type").getAsString());
      assertEquals(proxy, body.get("proxy").getAsString());
    }
  }

  @Test
  void aFailedTaskThrowsItsCode() throws Exception {
    try (StandInApi api = new StandInApi("failed")) {
      ZeroCaptchaException error =
          assertThrows(ZeroCaptchaException.class, () -> solver(api).solve(new TurnstileSolver.Task(PAGE, SITEKEY), TIMEOUT));
      assertEquals("ERROR_CAPTCHA_UNSOLVABLE", error.code());
    }
  }

  @Test
  void aRateLimitedCreateIsRetriedWithTheSameIdempotencyKey() throws Exception {
    try (StandInApi api = new StandInApi("rate-limited")) {
      assertEquals(StandInApi.TOKEN, solver(api).solve(new TurnstileSolver.Task(PAGE, SITEKEY), TIMEOUT));
      StandInApi.Recorded first = api.requests.get(0);
      StandInApi.Recorded second = api.requests.get(1);
      assertEquals("POST", second.method());
      assertEquals(first.idempotencyKey(), second.idempotencyKey());
    }
  }

  @Test
  void aRefusalIsThrownAtOnceWithItsRequestId() throws Exception {
    try (StandInApi api = new StandInApi("insufficient-funds")) {
      ZeroCaptchaException error =
          assertThrows(ZeroCaptchaException.class, () -> solver(api).solve(new TurnstileSolver.Task(PAGE, SITEKEY), TIMEOUT));
      assertEquals("insufficient_funds", error.code());
      assertNotNull(error.requestId());
      assertEquals(1, api.requests.size());
    }
  }

  @Test
  void theDeadlineStopsTheWait() throws Exception {
    try (StandInApi api = new StandInApi("success")) {
      TurnstileSolver slow = new TurnstileSolver(api.url(), StandInApi.KEY, Duration.ofSeconds(1));
      ZeroCaptchaException error =
          assertThrows(
              ZeroCaptchaException.class,
              () -> slow.solve(new TurnstileSolver.Task(PAGE, SITEKEY), Duration.ofMillis(300)));
      assertEquals("timeout", error.code());
    }
  }
}
