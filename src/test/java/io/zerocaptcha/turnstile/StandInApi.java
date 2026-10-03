package io.zerocaptcha.turnstile;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A stand-in for the ZeroCaptcha REST API on this machine, so the tests make no real task. It
 * answers POST /v1/tasks and GET /v1/tasks/{id} as the API does, records every request, and plays
 * one scenario: "success", "failed", "rate-limited" (the first create is 429 with Retry-After: 0)
 * or "insufficient-funds".
 */
final class StandInApi implements AutoCloseable {
  static final String KEY = "zc_live_test_key";
  static final String TASK_ID = "0192f3a4-7b1c-7d2e-9f10-3c4d5e6f7a8b";
  static final String TOKEN = "0.stand-in-turnstile-token";

  record Recorded(String method, String path, String authorization, String idempotencyKey, JsonObject body) {}

  final List<Recorded> requests = new CopyOnWriteArrayList<>();
  private final HttpServer server;
  private final String scenario;
  private int creates;
  private int polls;

  StandInApi(String scenario) throws IOException {
    this.scenario = scenario;
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", this::handle);
    server.start();
  }

  String url() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  @Override
  public void close() {
    server.stop(0);
  }

  private synchronized void handle(HttpExchange exchange) throws IOException {
    String text = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    JsonObject body = text.isEmpty() ? null : JsonParser.parseString(text).getAsJsonObject();
    String method = exchange.getRequestMethod();
    String path = exchange.getRequestURI().getPath();
    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
    requests.add(
        new Recorded(method, path, authorization, exchange.getRequestHeaders().getFirst("Idempotency-Key"), body));
    if (!("Bearer " + KEY).equals(authorization)) {
      problem(exchange, 401, "unauthorized");
    } else if (method.equals("POST") && path.equals("/v1/tasks")) {
      creates++;
      if (scenario.equals("rate-limited") && creates == 1) {
        exchange.getResponseHeaders().set("Retry-After", "0");
        problem(exchange, 429, "rate_limited");
      } else if (scenario.equals("insufficient-funds")) {
        problem(exchange, 402, "insufficient_funds");
      } else {
        reply(exchange, 201, task("queued"));
      }
    } else if (method.equals("GET") && path.equals("/v1/tasks/" + TASK_ID)) {
      polls++;
      if (scenario.equals("failed")) {
        JsonObject failed = task("failed");
        failed.addProperty("errorCode", "ERROR_CAPTCHA_UNSOLVABLE");
        failed.addProperty("errorDescription", "Every attempt failed.");
        reply(exchange, 200, failed);
      } else if (polls == 1) {
        reply(exchange, 200, task("running"));
      } else {
        JsonObject succeeded = task("succeeded");
        JsonObject solution = new JsonObject();
        solution.addProperty("token", TOKEN);
        succeeded.add("solution", solution);
        reply(exchange, 200, succeeded);
      }
    } else {
      problem(exchange, 404, "not_found");
    }
  }

  private static JsonObject task(String status) {
    JsonObject task = new JsonObject();
    task.addProperty("id", TASK_ID);
    task.addProperty("status", status);
    task.addProperty("kind", "turnstile");
    return task;
  }

  private static void problem(HttpExchange exchange, int status, String code) throws IOException {
    JsonObject problem = new JsonObject();
    problem.addProperty("type", "about:blank");
    problem.addProperty("title", code);
    problem.addProperty("status", status);
    problem.addProperty("detail", "The stand-in answered " + code + ".");
    problem.addProperty("code", code);
    problem.addProperty("request_id", "0192f3a4-0000-7000-8000-000000000000");
    reply(exchange, status, problem);
  }

  private static void reply(HttpExchange exchange, int status, JsonObject body) throws IOException {
    byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }
}
