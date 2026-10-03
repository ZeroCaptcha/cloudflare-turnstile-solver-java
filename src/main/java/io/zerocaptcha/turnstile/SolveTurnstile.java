package io.zerocaptcha.turnstile;

import java.time.Duration;

/**
 * Prints a Cloudflare Turnstile token for a page and its sitekey:
 *
 * <pre>
 * export ZEROCAPTCHA_API=https://api.zerocaptcha.io ZEROCAPTCHA_KEY=zc_live_...
 * mvn -q compile exec:java -Dexec.args="https://shop.example.com/login 0x4AAAAAAAB1cD2eF3gH4iJ5 login session-7f3a9c2e"
 * </pre>
 *
 * <p>The optional third and fourth arguments are the widget's data-action and data-cdata (or the
 * action and cData options of turnstile.render()): pass them whenever the widget sets them, since
 * many sites check both when they verify the token. Set PROXY_URL to solve through your own proxy.
 */
public final class SolveTurnstile {
  private SolveTurnstile() {}

  public static void main(String[] args) throws InterruptedException {
    if (args.length < 2 || args.length > 4) {
      System.err.println("Usage: SolveTurnstile <page URL> <sitekey> [action] [cdata]");
      System.exit(2);
    }
    String api = System.getenv("ZEROCAPTCHA_API");
    String key = System.getenv("ZEROCAPTCHA_KEY");
    if (api == null || api.isEmpty() || key == null || key.isEmpty()) {
      System.err.println("Set ZEROCAPTCHA_API and ZEROCAPTCHA_KEY first.");
      System.exit(2);
    }
    String proxy = System.getenv("PROXY_URL");
    TurnstileSolver.Task task =
        new TurnstileSolver.Task(
            args[0],
            args[1],
            args.length >= 3 ? args[2] : null, // the widget's action
            args.length == 4 ? args[3] : null, // the widget's cData
            proxy == null || proxy.isEmpty() ? null : proxy);
    try {
      System.out.println(new TurnstileSolver(api, key).solve(task, Duration.ofMinutes(3)));
    } catch (ZeroCaptchaException error) {
      String request = error.requestId() == null ? "" : " (request " + error.requestId() + ")";
      System.err.println(error.getMessage() + request);
      System.exit(1);
    }
  }
}
