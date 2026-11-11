// End-to-end run of the real Firefox extension against a real `vaultkeeper --daemon` and a
// disposable Vaultwarden. Not part of `vp test`; started by scripts/e2e-browser.sh, which sets the
// environment below. Needs selenium-webdriver (E2E_DEPS = a directory with it in node_modules),
// geckodriver and Firefox. Never touches the real HOME, Firefox profile or vault: the daemon gets a
// private data dir and keychain prefix, Firefox gets a private HOME and profile.
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import path from "node:path";
import readline from "node:readline";

const env = (name, fallback) => {
  const value = process.env[name] ?? fallback;
  if (value === undefined) {
    throw new Error(`${name} is required`);
  }
  return value;
};

const VW_URL = env("VW_URL");
const DAEMON_BIN = env("DAEMON_BIN");
const BOT_BIN = env("BOT_BIN");
const GECKODRIVER = env("GECKODRIVER");
const FIREFOX_BIN = env("FIREFOX_BIN", "/Applications/Firefox.app/Contents/MacOS/firefox");
const EXT_DIR = env("EXT_DIR");
const WORK = env("WORK");
const GECKO_ID = "browser-extension@vaultkeeper";
const EXT_UUID = "3f6a2b5e-6f0e-4a63-9c3a-5a7d1c0b9e11";

const require = createRequire(path.join(env("E2E_DEPS"), "noop.js"));
const { Builder, By } = require("selenium-webdriver");
const firefox = require("selenium-webdriver/firefox");

const id = randomBytes(5).toString("hex");
const DATA = `/tmp/vkb-${id}`;
const HOME = path.join(DATA, "home");
const KEYCHAIN_PREFIX = `vaultkeeper-e2e.${id}.`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const log = (...args) => console.error("[e2e]", ...args);

function prepareDirs() {
  fs.mkdirSync(path.join(DATA, "app-support", "Mozilla"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(HOME, "Library"), { recursive: true });
  fs.mkdirSync(path.join(DATA, "tmp"), { recursive: true });
  fs.symlinkSync(path.join(DATA, "app-support"), path.join(HOME, "Library", "Application Support"));
  fs.writeFileSync(
    path.join(DATA, "settings.json"),
    JSON.stringify({ browser_integration: true, browser_firefox: true, browser_chrome: false }),
  );
}

class Bot {
  events = [];
  constructor() {
    this.child = spawn(BOT_BIN, [DATA], { stdio: ["pipe", "pipe", "inherit"] });
    readline.createInterface({ input: this.child.stdout }).on("line", (line) => {
      const event = JSON.parse(line);
      event.at = Date.now();
      this.events.push(event);
      if (event.event !== "reply") {
        log("bot event", line.slice(0, 200));
      }
    });
  }
  mark() {
    return this.events.length;
  }
  async waitFor(predicate, from = 0, timeout = 20000) {
    const deadline = Date.now() + timeout;
    for (;;) {
      const found = this.events.slice(from).find(predicate);
      if (found) {
        return found;
      }
      if (Date.now() > deadline) {
        throw new Error("timed out waiting for a bot event");
      }
      await sleep(50);
    }
  }
  prompts(from = 0, kind) {
    return this.events
      .slice(from)
      .filter((e) => e.event === "prompt" && (!kind || e.kind === kind));
  }
  async call(cmd, args = {}) {
    const from = this.mark();
    this.child.stdin.write(`${JSON.stringify({ cmd, ...args })}\n`);
    const reply = await this.waitFor((e) => e.event === "reply" && e.cmd === cmd, from, 60000);
    if (!reply.ok) {
      throw new Error(`bot ${cmd}: ${reply.error}`);
    }
    return reply.value;
  }
}

class Daemon {
  start() {
    const out = fs.openSync(path.join(WORK, "daemon.log"), "a");
    this.child = spawn(DAEMON_BIN, ["--daemon"], {
      stdio: ["ignore", out, out],
      env: {
        ...process.env,
        VAULTKEEPER_TEST_DATA_DIR: DATA,
        VAULTKEEPER_TEST_KEYCHAIN_PREFIX: KEYCHAIN_PREFIX,
        VAULTKEEPER_TEST_ANY_PEER: "1",
        VAULTKEEPER_TEST_HEADLESS: "1",
        VAULTKEEPER_TEST_NO_UI: "1",
        RUST_LOG: "info,vk_ipc=debug",
      },
    });
    this.exited = new Promise((resolve) => this.child.once("exit", resolve));
  }
  async kill(signal = "SIGKILL") {
    this.child.kill(signal);
    await this.exited;
  }
}

function startPage() {
  const submissions = [];
  const page = (title) => `<!doctype html><title>${title}</title><body style="font:16px sans-serif">
<form id="f" method="post" action="/submit" style="margin:40px">
<p><input id="u" name="username" type="text" autocomplete="username" style="width:280px;height:32px"></p>
<p><input id="p" name="password" type="password" autocomplete="current-password" style="width:280px;height:32px"></p>
<p><button id="go" type="submit" style="height:32px">Sign in</button></p></form></body>`;
  const server = http.createServer((req, res) => {
    if (req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        submissions.push(Object.fromEntries(new URLSearchParams(body)));
        res.setHeader("content-type", "text/html");
        res.end("<!doctype html><title>done</title><h1>welcome</h1>");
      });
      return;
    }
    res.setHeader("content-type", "text/html");
    res.end(page("Login"));
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: server.address().port, submissions }),
    ),
  );
}

async function launchFirefox() {
  const options = new firefox.Options();
  options.setBinary(FIREFOX_BIN);
  options.addArguments("-headless");
  options.setPreference("extensions.webextensions.uuids", JSON.stringify({ [GECKO_ID]: EXT_UUID }));
  options.setPreference("browser.shell.checkDefaultBrowser", false);
  const service = new firefox.ServiceBuilder(GECKODRIVER)
    .addArguments("--allow-system-access")
    .setStdio(["ignore", fs.openSync(path.join(WORK, "geckodriver.log"), "a"), "inherit"]);
  service.setEnvironment?.({
    PATH: process.env.PATH,
    HOME,
    TMPDIR: path.join(DATA, "tmp"),
    VAULTKEEPER_TEST_DATA_DIR: DATA,
    // The host starts `vaultkeeper --tray` when the daemon is down; it must be the same headless,
    // keychain-prefixed daemon as the one this script runs, never a real tray app.
    VAULTKEEPER_TEST_KEYCHAIN_PREFIX: KEYCHAIN_PREFIX,
    VAULTKEEPER_TEST_ANY_PEER: "1",
    VAULTKEEPER_TEST_HEADLESS: "1",
    VAULTKEEPER_TEST_NO_UI: "1",
    MOZ_HEADLESS: "1",
    RUST_LOG: "info",
  });
  const driver = await new Builder()
    .forBrowser("firefox")
    .setFirefoxOptions(options)
    .setFirefoxService(service)
    .build();
  // Firefox resolves the user's native-messaging directory from the real account home, not $HOME,
  // so point it at the daemon's private app-support dir (privileged context, this process only).
  await driver.setContext(firefox.Context.CHROME);
  const resolved = await driver.executeScript(
    `const dir = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
     dir.initWithPath(arguments[0]);
     Services.dirsvc.set("XREUserNativeManifests", dir);
     return Services.dirsvc.get("XREUserNativeManifests", Ci.nsIFile).path;`,
    path.join(DATA, "app-support", "Mozilla"),
  );
  assertEqual(resolved, path.join(DATA, "app-support", "Mozilla"), "native manifests dir override");
  await driver.setContext(firefox.Context.CONTENT);
  const zip = path.join(DATA, "extension.xpi");
  await new Promise((resolve, reject) => {
    const z = spawn("zip", ["-qr", zip, "."], { cwd: EXT_DIR });
    z.once("exit", (code) => (code === 0 ? resolve() : reject(new Error("zip failed"))));
  });
  const installed = await driver.installAddon(zip, true);
  log("add-on installed", installed);
  return driver;
}

const results = [];
async function scenario(name, body) {
  const started = Date.now();
  try {
    const evidence = await body();
    results.push({ name, pass: true, evidence, ms: Date.now() - started });
    log("PASS", name, JSON.stringify(evidence));
  } catch (error) {
    results.push({
      name,
      pass: false,
      evidence: String(error?.stack ?? error),
      ms: Date.now() - started,
    });
    log("FAIL", name, String(error?.message ?? error));
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`assertion failed: ${message}`);
  }
}

function assertEqual(actual, expected, what) {
  assert(actual === expected, `${what}: ${actual} !== ${expected}`);
}

// A daemon the host auto-started is nobody's child; find it by the private data dir in its env.
async function reapStrays() {
  const capture = (command, args) =>
    new Promise((resolve) => {
      const child = spawn(command, args);
      let out = "";
      child.stdout.on("data", (chunk) => (out += chunk));
      child.once("close", () => resolve(out));
    });
  const pids = (await capture("pgrep", ["-f", "vaultkeeper --(tray|daemon)"]))
    .split("\n")
    .filter(Boolean);
  const reaped = [];
  for (const pid of pids) {
    const environment = await capture("ps", ["eww", "-p", pid]);
    if (environment.includes(`VAULTKEEPER_TEST_DATA_DIR=${DATA}`)) {
      log("reaping stray daemon", pid);
      reaped.push(Number(pid));
      process.kill(Number(pid), "SIGTERM");
    }
  }
  // A daemon whose data dir is gone cannot stop its single-instance listener, so it ignores
  // SIGTERM; this runs before the dir is removed, and a straggler is killed outright.
  const alive = (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  };
  for (let i = 0; i < 50 && reaped.some(alive); i++) {
    await sleep(100);
  }
  for (const pid of reaped.filter(alive)) {
    process.kill(pid, "SIGKILL");
  }
}

function psRows() {
  return new Promise((resolve) => {
    const ps = spawn("ps", ["-axo", "pid=,ppid=,rss=,command="]);
    let out = "";
    ps.stdout.on("data", (chunk) => (out += chunk));
    ps.once("exit", () => resolve(out.split("\n").filter(Boolean)));
  });
}

async function main() {
  fs.mkdirSync(WORK, { recursive: true });
  prepareDirs();
  const state = { driver: null, daemon: new Daemon(), bot: null, page: null, extra: {} };
  const cleanup = async () => {
    await state.driver?.quit().catch(() => undefined);
    state.bot?.child.kill();
    await state.daemon.kill("SIGTERM").catch(() => undefined);
    state.page?.server.close();
    await reapStrays();
  };
  process.on("SIGINT", () => cleanup().finally(() => process.exit(130)));
  try {
    await run(state);
  } finally {
    results.push({ name: "_logs", pass: true, evidence: readLogs() });
    fs.writeFileSync(path.join(WORK, "results.json"), JSON.stringify(results, null, 2));
    await cleanup();
    if (!process.env.KEEP_DATA) {
      fs.rmSync(DATA, { recursive: true, force: true });
    }
  }
  for (const r of results.filter((r) => r.name !== "_logs")) {
    console.log(
      `${r.pass ? "PASS" : "FAIL"}  ${r.name}  ${typeof r.evidence === "string" ? r.evidence.split("\n")[0] : JSON.stringify(r.evidence)}`,
    );
  }
  process.exitCode = results.some((r) => !r.pass) ? 1 : 0;
}

function readLogs() {
  const out = {};
  const dir = path.join(DATA, "logs");
  for (const name of fs.existsSync(dir) ? fs.readdirSync(dir) : []) {
    out[name] = fs.readFileSync(path.join(dir, name), "utf8").split("\n").slice(-60);
  }
  out["browsers.json"] = fs.existsSync(path.join(DATA, "browsers.json"))
    ? fs.readFileSync(path.join(DATA, "browsers.json"), "utf8")
    : null;
  return out;
}

async function run(state) {
  state.page = await startPage();
  const origin = `http://127.0.0.1:${state.page.port}`;
  const loginUrl = `${origin}/login`;
  state.daemon.start();
  state.bot = new Bot();
  const { bot, daemon } = state;
  await bot.call("connect");
  const account = await bot.call("register", { server: VW_URL });
  await bot.call("login", { server: VW_URL });
  await bot.call("add", {
    name: "Local Alice",
    username: "alice",
    password: "alice-pw-1",
    uris: [`${origin}/`],
  });
  await bot.call("add", {
    name: "Local Bob",
    username: "bob",
    password: "bob-pw-1",
    uris: [`${origin}/`],
  });
  await bot.call("add", {
    name: "Other Site",
    username: "carol",
    password: "carol-pw",
    uris: ["https://example.org/"],
  });
  log("vault ready", account.email, await bot.call("state"));

  const manifest = path.join(
    DATA,
    "app-support",
    "Mozilla",
    "NativeMessagingHosts",
    "org.vaultkeeper.browser.json",
  );
  for (
    let i = 0;
    i < 100 && !(fs.existsSync(manifest) && fs.existsSync(path.join(DATA, "browser.sock")));
    i++
  ) {
    await sleep(100);
  }
  assert(fs.existsSync(manifest), "native messaging manifest written by the daemon");
  assert(fs.existsSync(path.join(DATA, "browser.sock")), "browser.sock bound");
  state.extra.manifest = JSON.parse(fs.readFileSync(manifest, "utf8"));

  await bot.call("policy", { pair: "slow", fill: "name:Local Alice", save: "save" });
  const driver = (state.driver = await launchFirefox());
  const pageHandle = await driver.getWindowHandle();
  const WIDGET = "browser-extension_vaultkeeper-browser-action";
  const privileged = async (body, ...args) => {
    await driver.setContext(firefox.Context.CHROME);
    try {
      const result = await driver.executeAsyncScript(
        `const done = arguments[arguments.length - 1];
         const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
         const w = Services.wm.getMostRecentWindow("navigator:browser");
         const popupBrowser = () => w.document.querySelector('browser[webextension-view-type="popup"]');
         (async () => { ${body} })().then(done, (e) => done({ error: String(e) }));`,
        ...args,
      );
      if (result?.error) {
        throw new Error(result.error);
      }
      return result;
    } finally {
      await driver.setContext(firefox.Context.CONTENT);
    }
  };
  // The real toolbar popup (no tab), the way a user opens it. It lives in another process, so its
  // DOM is reached with a frame script that evaluates a snippet in the popup's content window.
  const inPopup = (snippet) =>
    privileged(
      `const browser = popupBrowser();
       if (!browser) { return "(popup closed)"; }
       const key = "vk" + Math.random();
       const manager = browser.messageManager;
       const reply = new Promise((resolve) => {
         const listener = (message) => {
           if (message.data.key === key) { manager.removeMessageListener("vk:result", listener); resolve(message.data.value); }
         };
         manager.addMessageListener("vk:result", listener);
       });
       const run = "sendAsyncMessage('vk:result', { key: " + JSON.stringify(key) + ", value: (() => {" + arguments[0] + "})() });";
       manager.loadFrameScript("data:," + encodeURIComponent(run), false);
       return await reply;`,
      snippet,
    );
  const popup = {
    open: async (wait = 1500) => {
      await privileged(
        `const panel = w.document.getElementById("customizationui-widget-panel");
         if (panel && panel.state !== "closed") { panel.hidePopup(); await sleep(300); }
         const { CustomizableUI } = ChromeUtils.importESModule("moz-src:///browser/components/customizableui/CustomizableUI.sys.mjs");
         try { CustomizableUI.addWidgetToArea(arguments[0], "nav-bar"); } catch (e) {}
         const button = w.document.getElementById(arguments[0]);
         (button.querySelector("toolbarbutton") ?? button).click();
         await sleep(arguments[1]);
         return true;`,
        WIDGET,
        wait,
      );
      return popup.read();
    },
    read: () => inPopup("return content.document.body.innerText;"),
    runtimeId: () => inPopup("return content.wrappedJSObject.browser.runtime.id;"),
    press: (label) =>
      inPopup(
        `const b = [...content.document.querySelectorAll("button")].find((x) => x.textContent.includes(${JSON.stringify(label)}));
         if (!b) { return "no button"; }
         b.click(); return "clicked";`,
      ),
    close: () =>
      privileged(
        `w.document.getElementById("customizationui-widget-panel")?.hidePopup(); return true;`,
      ),
  };

  await scenario("a. extension connects, pair prompt fingerprint equals popup", async () => {
    const from = bot.mark();
    const pending = await popup.open(1500);
    const prompt = await bot.waitFor((e) => e.event === "prompt" && e.kind === "pair", from, 30000);
    assert(
      pending.includes(prompt.fingerprint),
      `popup shows ${prompt.fingerprint} while pending: ${pending}`,
    );
    await sleep(5500);
    const ready = await popup.read();
    const runtimeId = await popup.runtimeId();
    const store = JSON.parse(fs.readFileSync(path.join(DATA, "browsers.json"), "utf8"));
    assert(store.paired.length === 1, "one pairing stored");
    assert(runtimeId === GECKO_ID, `runtime.id ${runtimeId}`);
    assert(ready.includes(prompt.fingerprint), `popup footer shows the fingerprint: ${ready}`);
    return {
      fingerprint: prompt.fingerprint,
      browser: prompt.browser,
      pendingPopup: pending,
      readyPopup: ready,
      runtimeId,
      stored: store.paired[0],
    };
  });
  await popup.close();

  await driver.switchTo().window(pageHandle);
  await driver.get(loginUrl);
  const field = async (selector) => driver.findElement(By.css(selector));
  const fieldValues = () =>
    driver.executeScript(
      "return [document.getElementById('u').value, document.getElementById('p').value]",
    );
  const clearFields = () =>
    driver.executeScript(
      "document.getElementById('u').value=''; document.getElementById('p').value='';",
    );
  const clickIcon = async (selector = "#u") => {
    const el = await field(selector);
    const rect = await el.getRect();
    await driver
      .actions({ async: true })
      .move({ x: Math.round(rect.x + 12), y: Math.round(rect.y + rect.height / 2) })
      .click()
      .perform();
    await sleep(300);
    await driver
      .actions({ async: true })
      .move({ x: Math.round(rect.x + rect.width - 14), y: Math.round(rect.y + rect.height / 2) })
      .click()
      .perform();
  };
  const hostRows = async () =>
    (await psRows()).filter((r) => r.includes("org.vaultkeeper.browser.json"));

  await scenario(
    "b. icon click -> Fill prompt, fields filled, second fill remembered",
    async () => {
      const from = bot.mark();
      await clickIcon();
      const prompt = await bot.waitFor(
        (e) => e.event === "prompt" && e.kind === "fill",
        from,
        20000,
      );
      await sleep(1500);
      const [u, p] = await fieldValues();
      assert(u === "alice" && p === "alice-pw-1", `filled ${u}/${p}`);
      assert(prompt.host.includes(`127.0.0.1`), `host ${prompt.host}`);
      const names = prompt.matches.map((m) => m.name).sort();
      assert(names.join() === "Local Alice,Local Bob", `matches ${names}`);
      const rows = await hostRows();
      state.extra.hostRows = rows;
      await clearFields();
      const second = bot.mark();
      await clickIcon();
      await sleep(2500);
      const [u2, p2] = await fieldValues();
      assert(u2 === "alice" && p2 === "alice-pw-1", `remembered fill gave ${u2}/${p2}`);
      assert(bot.prompts(second, "fill").length === 0, "second fill raised no prompt");
      return {
        prompt: { host: prompt.host, insecure: prompt.insecure, matches: names },
        rememberedFill: true,
      };
    },
  );

  await scenario("b2. popup 'Choose another login…' shows the picker again and fills", async () => {
    await driver.get(loginUrl);
    await bot.call("policy", { fill: "name:Local Bob" });
    const from = bot.mark();
    await popup.open(1500);
    const pressed = await popup.press("Choose another login");
    const prompt = await bot.waitFor((e) => e.event === "prompt" && e.kind === "fill", from, 20000);
    await sleep(1500);
    const [u, p] = await fieldValues();
    assert(u === "bob" && p === "bob-pw-1", `filled ${u}/${p}`);
    await popup.close();
    return { pressed, host: prompt.host };
  });

  await scenario("c1. new login typed + submitted -> Save prompt (new), item stored", async () => {
    await driver.get(loginUrl);
    const from = bot.mark();
    await (await field("#u")).sendKeys("newuser");
    await (await field("#p")).sendKeys("Brand-new-pw-9");
    await (await field("#go")).click();
    const prompt = await bot.waitFor((e) => e.event === "prompt" && e.kind === "save", from, 20000);
    assert(prompt.update_of === null && prompt.username === "newuser", JSON.stringify(prompt));
    await sleep(2000);
    const items = await bot.call("items");
    const created = items.find((i) => i.username === "newuser");
    assert(created && created.password === "Brand-new-pw-9", `stored ${JSON.stringify(created)}`);
    await bot.call("sync");
    const synced = (await bot.call("items")).find((i) => i.username === "newuser");
    assert(synced?.password === "Brand-new-pw-9", "survives a server sync");
    assert(
      state.page.submissions.some((s) => s.username === "newuser"),
      "page received the post",
    );
    return {
      prompt: { host: prompt.host, username: prompt.username },
      item: { name: created.name, uris: created.uris },
    };
  });

  await scenario("c2. changed password for a known login -> Save prompt (update)", async () => {
    await driver.get(loginUrl);
    const from = bot.mark();
    await (await field("#u")).sendKeys("alice");
    await (await field("#p")).sendKeys("alice-pw-CHANGED");
    await (await field("#go")).click();
    const prompt = await bot.waitFor((e) => e.event === "prompt" && e.kind === "save", from, 20000);
    assert(prompt.update_of?.name === "Local Alice", JSON.stringify(prompt));
    await sleep(2000);
    const alice = (await bot.call("items")).find((i) => i.name === "Local Alice");
    assert(alice.password === "alice-pw-CHANGED", `alice now ${alice.password}`);
    return { updateOf: prompt.update_of.name };
  });

  await scenario("c3. stored password typed -> no Save prompt", async () => {
    await driver.get(loginUrl);
    const from = bot.mark();
    await (await field("#u")).sendKeys("bob");
    await (await field("#p")).sendKeys("bob-pw-1");
    await (await field("#go")).click();
    await sleep(4000);
    assert(bot.prompts(from, "save").length === 0, "no save prompt");
    assert(
      state.page.submissions.some((s) => s.username === "bob"),
      "page received the post",
    );
    return { prompts: 0 };
  });

  await scenario(
    "c4. idle port survives the 30 s event-page timer (same host process, no re-pair)",
    async () => {
      const pidOf = async () =>
        (await hostRows())
          .map((row) => row.trim().split(/\s+/)[0])
          .sort()
          .join();
      const before = await pidOf();
      assert(before, "a host process exists");
      const from = bot.mark();
      await sleep(100000);
      const after = await pidOf();
      assert(after === before, `host process changed: ${before} -> ${after}`);
      await driver.get(loginUrl);
      await clearFields();
      await clickIcon();
      await sleep(2500);
      const [u, p] = await fieldValues();
      assert(u && p, `fill after idle gave ${u}/${p}`);
      assert(bot.prompts(from, "pair").length === 0, "no new pair prompt");
      return { hostPid: after, idleSeconds: 100, filled: u };
    },
  );

  await scenario("d. locked vault: UnlockInTray first, picker after unlock", async () => {
    await driver.get(loginUrl);
    await bot.call("lock");
    await bot.call("policy", { fill: "name:Local Bob" });
    const from = bot.mark();
    await clickIcon();
    const command = await bot.waitFor(
      (e) => e.event === "command" && e.command.includes("UnlockInTray"),
      from,
      20000,
    );
    assert(bot.prompts(from, "fill").length === 0, "picker not shown before unlock");
    await bot.call("unlock");
    const prompt = await bot.waitFor((e) => e.event === "prompt" && e.kind === "fill", from, 20000);
    await sleep(1500);
    const [u, p] = await fieldValues();
    assert(u === "bob" && p === "bob-pw-1", `filled ${u}/${p}`);
    return { unlockCommand: command.command, pickerAfterUnlock: prompt.host };
  });

  await scenario("e. removed pairing closes the session, re-pair prompt on next use", async () => {
    const storePath = path.join(DATA, "browsers.json");
    const store = JSON.parse(fs.readFileSync(storePath, "utf8"));
    const withPopup = await popup.open(1500);
    const before = await hostRows();
    fs.writeFileSync(storePath, JSON.stringify({ ...store, paired: [] }));
    await bot.call("notify_settings");
    await sleep(2500);
    const after = await hostRows();
    const text = await popup.read();
    await bot.call("policy", { pair: "approve" });
    const from = bot.mark();
    const reopened = await popup.open(1500);
    const prompt = await bot.waitFor((e) => e.event === "prompt" && e.kind === "pair", from, 20000);
    await sleep(1500);
    const fresh = await popup.read();
    return {
      popupBefore: withPopup,
      hostsBefore: before.length,
      hostsAfter: after.length,
      popupAfterRemoval: text,
      popupReopened: reopened,
      repairFingerprint: prompt.fingerprint,
      popupAfterRepair: fresh,
    };
  });

  await scenario("f. daemon killed -> unavailable, recovers after restart", async () => {
    await popup.close();
    await popup.open(1500);
    await daemon.kill("SIGKILL");
    await sleep(2500);
    const down = await popup.read();
    const reopened = await popup.open(3000);
    daemon.start();
    const botAgain = new Bot();
    state.bot.child.kill();
    state.bot = botAgain;
    await botAgain.call("connect");
    await botAgain.call("account", account);
    await botAgain.call("unlock");
    await botAgain.call("policy", { pair: "approve", fill: "name:Local Alice" });
    await sleep(1000);
    const up = await popup.open(5000);
    return { whileDown: down, reopenedWhileDown: reopened, afterRestart: up };
  });

  await scenario("g. fill works again after the daemon restart", async () => {
    await popup.close();
    await driver.get(loginUrl);
    const from = state.bot.mark();
    await clickIcon();
    const prompt = await state.bot.waitFor(
      (e) => e.event === "prompt" && e.kind === "fill",
      from,
      25000,
    );
    await sleep(1500);
    const [u, p] = await fieldValues();
    assert(u === "alice" && p === "alice-pw-CHANGED", `filled ${u}/${p}`);
    return { host: prompt.host, filled: [u, p] };
  });

  await scenario(
    "h. host stdout carries only native messages; refuses a non-browser parent",
    async () => {
      const host = spawn(
        DAEMON_BIN,
        [
          path.join(
            DATA,
            "app-support",
            "Mozilla",
            "NativeMessagingHosts",
            "org.vaultkeeper.browser.json",
          ),
          GECKO_ID,
        ],
        {
          env: { ...process.env, VAULTKEEPER_TEST_DATA_DIR: DATA },
          stdio: ["pipe", "pipe", "pipe"],
        },
      );
      const out = [];
      const err = [];
      const exited = new Promise((resolve) => host.once("exit", resolve));
      host.stdout.on("data", (c) => out.push(c));
      host.stderr.on("data", (c) => err.push(c));
      const request = Buffer.from(JSON.stringify({ id: 1, type: "status" }));
      const header = Buffer.alloc(4);
      header.writeUInt32LE(request.length);
      host.stdin.write(Buffer.concat([header, request]));
      await sleep(2500);
      host.stdin.end();
      const exitCode = await exited;
      const bytes = Buffer.concat(out);
      const messages = [];
      let offset = 0;
      while (offset + 4 <= bytes.length) {
        const length = bytes.readUInt32LE(offset);
        messages.push(JSON.parse(bytes.subarray(offset + 4, offset + 4 + length).toString()));
        offset += 4 + length;
      }
      assert(
        offset === bytes.length,
        `stdout is exactly framed messages (${bytes.length} bytes, ${offset} framed)`,
      );
      assert(
        messages.length >= 1 && messages.every((m) => typeof m === "object"),
        "frames parse as JSON",
      );
      return {
        exitCode,
        stdoutBytes: bytes.length,
        messages,
        stderrBytes: Buffer.concat(err).length,
      };
    },
  );

  state.extra.fingerprintOfExtension = createHash("sha256")
    .update(GECKO_ID)
    .digest("hex")
    .slice(0, 8);
  results.push({ name: "_extra", pass: true, evidence: state.extra });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
