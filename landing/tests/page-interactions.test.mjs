import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
import vm from "node:vm";

const page = readFileSync(new URL("../src/pages/index.astro", import.meta.url), "utf8");
const script = stripTypeScriptTypes(page.match(/<script>\s*([\s\S]*?)<\/script>/)[1]
  .replace(/import \{[^}]+\} from [^;]+;/, "")
  .replaceAll("import.meta.env.DEV", "false"));

// Run the actual page controller with controlled layout, events and timers. Artwork is
// stubbed here; its renderers and destruction are exercised by the particle tests.
// One screen of the story is SCREEN_PX of scroll, and the story starts at the top of the page.
const SCREEN_PX = 800;
function environment({ fits = true, scrollY = 0 } = {}) {
  class Events {
    listeners = new Map();
    addEventListener(name, fn) {
      if (!this.listeners.has(name)) this.listeners.set(name, new Set());
      this.listeners.get(name).add(fn);
    }
    removeEventListener(name, fn) { this.listeners.get(name)?.delete(fn); }
    async dispatch(name, event = {}) {
      await Promise.all([...this.listeners.get(name) ?? []].map((fn) => fn(event)));
    }
  }
  class Element extends Events {
    hidden = false;
    inert = false;
    dataset = {};
    attributes = new Map();
    classes = new Set();
    clientWidth = 460;
    clientHeight = 320;
    offsetHeight = 0;
    style = {
      transform: "",
      removeProperty(name) { if (name === "transform") this.transform = ""; },
    };
    classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      contains: (name) => this.classes.has(name),
      toggle: (name, on) => on ? this.classes.add(name) : this.classes.delete(name),
    };
    focus() { doc.activeElement = this; }
    setAttribute(name, value) { this.attributes.set(name, value); }
    removeAttribute(name) { this.attributes.delete(name); }
    contains(el) { return el === this || el?.parent === this; }
    closest() { return null; }
    querySelector() { return null; }
    getBoundingClientRect() { return { top: 100, bottom: 500, left: 32, right: 700, width: 668, height: 400 }; }
  }
  const ids = Object.fromEntries([
    "particles", "story", "a11y-menu", "a11y-trigger", "a11y-panel", "a11y-close",
    "a11y-reduced-note", "motion-row", "motion-toggle", "graphics-row", "graphics-toggle",
    "scene-rail", "main-content", "story-plan",
    "toast", "toast-title", "toast-sub", "toast-close",
  ].map((id) => [id, new Element()]));
  ids["a11y-panel"].hidden = true;
  ids["a11y-panel"].parent = ids["a11y-menu"];
  ids["a11y-trigger"].parent = ids["a11y-menu"];
  ids["story-plan"].textContent = JSON.stringify([["hero", 0.95], ["alone", 1.25], ["swarm", 1.25], ["robot", 2.85], ["end", 0.95]]);
  ids.particles.clientHeight = 800;
  ids.particles.getBoundingClientRect = () => ({ top: 0, bottom: 800, left: 0, right: 1280 });
  ids.story.dataset.screens = "7.5";
  ids.story.getBoundingClientRect = () => ({ top: -win.scrollY, bottom: 8.5 * SCREEN_PX - win.scrollY, left: 0, right: 1280 });
  const spacer = new Element();
  spacer.offsetHeight = 7.5 * SCREEN_PX;
  ids.story.querySelector = () => spacer;
  const content = new Element();
  content.getBoundingClientRect = () => ({ top: 100, bottom: fits ? 500 : 850, left: 32, right: 700 });
  ids.story.querySelectorAll = () => [content];
  ids.toast.hidden = true;
  ids["toast-close"].parent = ids.toast;
  const toastLink = new Element();
  toastLink.parent = ids.toast;
  const setup = new Element();
  setup.dataset.prompt = "Install FinishUP";
  const copies = ["hero", "alone", "swarm", "robot1", "robot2", "robot3", "end"].map((copy) => {
    const el = new Element();
    el.dataset.copy = copy;
    return el;
  });
  const stills = ["hero", "alone", "swarm", "robot", "robot", "robot", "end"].map((form) => {
    const el = new Element();
    el.dataset.stillForm = form;
    el.dataset.stillPhase = "0.5";
    return el;
  });
  const railDots = ["hero", "alone", "swarm", "robot1", "end"].map((target) => {
    const el = new Element();
    el.dataset.sceneTarget = target;
    return el;
  });
  let finishFonts;
  const doc = Object.assign(new Events(), {
    activeElement: setup,
    documentElement: { scrollHeight: 8.5 * SCREEN_PX + 95 },
    fonts: { ready: new Promise((resolve) => { finishFonts = resolve; }) },
    getElementById: (id) => ids[id],
    querySelectorAll: (selector) => {
      if (selector === ".copy") return copies;
      if (selector === ".still-art") return stills;
      if (selector === ".rail-dot") return railDots;
      return [setup];
    },
    querySelector: () => null,
  });
  const queries = new Map();
  const timers = new Map();
  const frames = new Map();
  let nextId = 0;
  let activeArt = 0;
  let stillRenders = 0;
  const win = Object.assign(new Events(), {
    scrollY,
    scrollTo({ top }) { this.scrollY = top; },
    matchMedia(query) {
      const media = Object.assign(new Events(), { matches: false });
      queries.set(query, media);
      return media;
    },
    setTimeout(fn) { const id = ++nextId; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  const context = vm.createContext({
    window: win, document: doc, innerWidth: 1280, innerHeight: 800,
    HTMLElement: Element, CanvasRenderingContext2D: class {}, CSS: { supports: () => true },
    navigator: { clipboard: { writeText: async () => {} } },
    performance: { now: () => 0 },
    requestAnimationFrame(fn) { const id = ++nextId; frames.set(id, fn); return id; },
    cancelAnimationFrame(id) { frames.delete(id); },
    mountParticles() {
      activeArt++;
      return { renderer: "webgl", setScroll() {}, setLockup() {}, destroy() { activeArt--; } };
    },
    renderStills(items) {
      stillRenders += items.length;
      return true;
    },
  });
  vm.runInContext(script, context, { timeout: 1000 });
  return {
    ids, doc, win, context, setup, toastLink, copies, stills, railDots, queries, timers, finishFonts,
    get activeArt() { return activeArt; },
    get stillRenders() { return stillRenders; },
    setFits(value) { fits = value; },
    expireTimers() {
      const callbacks = [...timers.values()];
      timers.clear();
      for (const fn of callbacks) fn();
    },
  };
}

test("a hovered toast survives focus leaving, and expires only after hover and focus leave", async () => {
  const env = environment();
  await env.setup.dispatch("click");
  assert.equal(env.ids.toast.hidden, false);
  await env.ids.toast.dispatch("pointerenter");
  env.doc.activeElement = env.toastLink;
  await env.ids.toast.dispatch("focusin");
  env.doc.activeElement = env.setup;
  await env.ids.toast.dispatch("focusout", { relatedTarget: env.setup });
  assert.equal(env.timers.size, 0, "focus leaving cannot start a timer while still hovered");
  env.expireTimers();
  assert.equal(env.ids.toast.hidden, false);
  env.doc.activeElement = env.toastLink;
  await env.ids.toast.dispatch("pointerleave");
  assert.equal(env.timers.size, 0, "leaving with the pointer cannot hide a focused link");
  env.doc.activeElement = env.setup;
  await env.ids.toast.dispatch("focusout", { relatedTarget: env.setup });
  assert.equal(env.timers.size, 1);
  env.expireTimers();
  assert.equal(env.ids.toast.hidden, true);
});

test("pause destroys the artwork, renders static stills, and play restores animation", async () => {
  const env = environment();
  const toggle = env.ids["motion-toggle"];
  assert.equal(toggle.hidden, false);
  assert.equal(env.ids["a11y-menu"].hidden, false);
  assert.equal(env.activeArt, 1);
  assert.equal(env.stillRenders, 0);
  await toggle.dispatch("click");
  assert.equal(env.activeArt, 0);
  assert.equal(env.ids.story.classList.contains("animated"), false);
  assert.equal(env.ids.story.classList.contains("stills"), true);
  assert.equal(env.stillRenders, 7, "every scene receives a crisp static still");
  assert.equal(toggle.attributes.get("aria-checked"), "true", "Pause motion is on");
  assert.ok(env.copies.every((el) => !el.inert && !el.attributes.has("aria-hidden")));
  await env.win.dispatch("resize");
  await env.win.dispatch("pagehide");
  await env.win.dispatch("pageshow", { persisted: true });
  assert.equal(env.activeArt, 0, "resize and history restoration preserve the visitor's pause");
  await toggle.dispatch("click");
  assert.equal(env.activeArt, 1);
  assert.equal(env.ids.story.classList.contains("animated"), true);
  assert.equal(env.ids.story.classList.contains("stills"), false);
  assert.equal(toggle.attributes.get("aria-checked"), "false", "Pause motion is off");
  assert.equal(toggle.attributes.has("aria-label"), false, "the switch is never renamed; aria-checked carries its state");
});

test("text-only toggle hides decorative stills and restores presentation cleanly", async () => {
  const env = environment();
  const trigger = env.ids["a11y-trigger"];
  const panel = env.ids["a11y-panel"];
  const graphics = env.ids["graphics-toggle"];
  assert.equal(panel.hidden, true);
  await trigger.dispatch("click");
  assert.equal(panel.hidden, false);
  assert.equal(trigger.attributes.get("aria-expanded"), "true");
  await graphics.dispatch("click");
  assert.equal(env.activeArt, 0);
  assert.equal(env.ids.story.classList.contains("animated"), false);
  assert.equal(env.ids.story.classList.contains("stills"), false);
  assert.equal(graphics.attributes.get("aria-checked"), "true", "Text only is on");
  assert.equal(env.ids["motion-toggle"].attributes.get("aria-checked"), "true", "text only also pauses motion");
  await env.doc.dispatch("keydown", { key: "Escape" });
  assert.equal(panel.hidden, true);
  await graphics.dispatch("click");
  assert.equal(env.activeArt, 1);
  assert.equal(env.ids.story.classList.contains("animated"), true);
  assert.equal(graphics.attributes.get("aria-checked"), "false", "Text only is off");
  assert.equal(env.ids["motion-toggle"].attributes.get("aria-checked"), "false");
  assert.equal(graphics.attributes.has("aria-label"), false, "the switch is never renamed; aria-checked carries its state");
  assert.equal(env.ids["motion-toggle"].attributes.has("aria-label"), false);
});

test("copy that cannot fit uses stills flow and animation returns when room is available", async () => {
  const env = environment({ fits: false });
  assert.equal(env.activeArt, 0, "do not mount artwork for a clipped story");
  assert.equal(env.ids.story.classList.contains("animated"), false);
  assert.equal(env.ids.story.classList.contains("stills"), true);
  assert.equal(env.ids["motion-toggle"].hidden, true);
  env.setFits(true);
  await env.win.dispatch("resize");
  assert.equal(env.activeArt, 1);
  env.setFits(false);
  env.finishFonts();
  await Promise.resolve();
  assert.equal(env.activeArt, 0, "a font load that makes copy overflow also switches to stills flow");
});

test("reduced motion shows stills while forced colours keep plain text only", async () => {
  const reducedEnv = environment();
  const reducedMedia = reducedEnv.queries.get("(prefers-reduced-motion: reduce)");
  reducedMedia.matches = true;
  await reducedMedia.dispatch("change");
  assert.equal(reducedEnv.activeArt, 0);
  assert.equal(reducedEnv.ids.story.classList.contains("stills"), true);
  assert.equal(reducedEnv.ids["motion-toggle"].hidden, true);
  assert.equal(reducedEnv.ids["a11y-reduced-note"].hidden, false);
  reducedMedia.matches = false;
  await reducedMedia.dispatch("change");
  assert.equal(reducedEnv.activeArt, 1);

  const forcedEnv = environment();
  const forcedMedia = forcedEnv.queries.get("(forced-colors: active)");
  forcedMedia.matches = true;
  await forcedMedia.dispatch("change");
  assert.equal(forcedEnv.activeArt, 0);
  assert.equal(forcedEnv.ids.story.classList.contains("stills"), false);
  assert.equal(forcedEnv.ids["a11y-menu"].hidden, true);
  forcedMedia.matches = false;
  await forcedMedia.dispatch("change");
  assert.equal(forcedEnv.activeArt, 1);
});

test("the accessibility menu opens under its trigger and gives focus back when it closes", async () => {
  const env = environment();
  const trigger = env.ids["a11y-trigger"];
  const panel = env.ids["a11y-panel"];
  const close = env.ids["a11y-close"];
  close.parent = panel;
  // Opening leaves focus on the trigger. The panel is the next thing in the page source (see
  // page.test.mjs), so the next Tab lands on its first control.
  env.doc.activeElement = trigger;
  await trigger.dispatch("click");
  assert.equal(panel.hidden, false);
  assert.equal(trigger.attributes.get("aria-expanded"), "true");
  assert.equal(env.doc.activeElement, trigger, "opening does not move focus");
  // The close button hides the panel it sits in, so focus goes back to the trigger.
  env.doc.activeElement = close;
  await close.dispatch("click");
  assert.equal(panel.hidden, true);
  assert.equal(trigger.attributes.get("aria-expanded"), "false");
  assert.equal(env.doc.activeElement, trigger, "the close button returns focus to the trigger");
  // Escape does the same from a control inside the panel.
  await trigger.dispatch("click");
  env.doc.activeElement = env.ids["graphics-toggle"];
  await env.doc.dispatch("keydown", { key: "Escape" });
  assert.equal(panel.hidden, true);
  assert.equal(trigger.attributes.get("aria-expanded"), "false");
  assert.equal(env.doc.activeElement, trigger, "Escape returns focus to the trigger");
  // The trigger closes the panel it opened.
  await trigger.dispatch("click");
  await trigger.dispatch("click");
  assert.equal(panel.hidden, true);
  assert.equal(trigger.attributes.get("aria-expanded"), "false");
  // A click elsewhere closes the panel and leaves focus where the click put it.
  await trigger.dispatch("click");
  await env.doc.dispatch("click", { target: trigger });
  assert.equal(panel.hidden, false, "a click inside the menu keeps it open");
  env.doc.activeElement = env.setup;
  await env.doc.dispatch("click", { target: env.setup });
  assert.equal(panel.hidden, true);
  assert.equal(trigger.attributes.get("aria-expanded"), "false");
  assert.equal(env.doc.activeElement, env.setup);
  // Escape with the panel closed is left alone.
  await env.doc.dispatch("keydown", { key: "Escape" });
  assert.equal(env.doc.activeElement, env.setup);
});

// The rail's current step and the copy shown, after scrolling this many screens into the story.
async function railAt(env, screens) {
  env.win.scrollY = screens * SCREEN_PX;
  await env.win.dispatch("scroll");
  return railNow(env);
}
function railNow(env) {
  const current = env.railDots.filter((dot) => dot.attributes.get("aria-current") === "step");
  assert.equal(current.length, 1, "exactly one step is current");
  assert.deepEqual(env.railDots.filter((dot) => dot.classes.has("on")), current, "the highlight is on the current step");
  return { step: current[0].dataset.sceneTarget, shown: env.copies.filter((el) => el.classes.has("on")).map((el) => el.dataset.copy) };
}
const RAIL_STEPS = ["hero", "alone", "swarm", "robot1", "end"];
// The three robot lines share one scene and one step.
const STEP_OF = { hero: "hero", alone: "alone", swarm: "swarm", robot1: "robot1", robot2: "robot1", robot3: "robot1", end: "end" };

test("the scene rail keeps a scene current through every crossfade, scrolling down and back up", async () => {
  const env = environment();
  const down = [];
  let gaps = 0;
  for (let i = 0; i <= 750; i++) {
    const { step, shown } = await railAt(env, i / 100);
    assert.ok(shown.length <= 1, "one copy at a time");
    // Where a copy is shown the rail names its scene; where none is, it still names a scene.
    if (shown.length) assert.equal(step, STEP_OF[shown[0]], `at ${i / 100} screens`);
    else gaps++;
    if (i > 0) {
      assert.ok(RAIL_STEPS.indexOf(step) >= RAIL_STEPS.indexOf(down[i - 1]),
        `at ${i / 100} screens the rail went back from ${down[i - 1]} to ${step}`);
    }
    down.push(step);
  }
  assert.ok(gaps > 20, "the scroll passes through stretches where no copy is shown");
  assert.deepEqual([...new Set(down)], RAIL_STEPS, "every step is current in turn, each once");
  // The step depends on the scroll position alone, so the way back passes the same steps.
  for (let i = 750; i >= 0; i--) assert.equal((await railAt(env, i / 100)).step, down[i], `back at ${i / 100} screens`);
});

test("between two scenes the rail marks the nearer one, also on a page loaded there", async () => {
  // "swarm" has faded out by 3.31 screens and "robot1" starts to fade in at 3.59.
  for (const [screens, step] of [[3.36, "swarm"], [3.43, "swarm"], [3.47, "robot1"], [3.56, "robot1"]]) {
    const loaded = environment({ scrollY: screens * SCREEN_PX });
    assert.deepEqual(railNow(loaded), { step, shown: [] }, `loaded at ${screens} screens`);
    assert.deepEqual(await railAt(environment(), screens), { step, shown: [] }, `scrolled to ${screens} screens`);
  }
  // The robot lines crossfade inside one scene; the step holds while neither line is fully in.
  assert.deepEqual(await railAt(environment(), 4.4), { step: "robot1", shown: [] });
  assert.deepEqual(await railAt(environment(), 5.35), { step: "robot1", shown: [] });
});

// The still and text views lay the copies out as an ordinary page. These are each copy's top
// and height in page pixels, and the page's height, as the built page measures them in a
// 1280x800 window. The window scrolls like a browser's: never past either end of the page.
const PAGES = {
  stills: { tops: [72, 670, 1103, 1536, 1969, 2402, 2835], heights: [598, 433, 433, 433, 433, 433, 554], height: 3483 },
  text: { tops: [72, 504, 731, 951, 1177, 1397, 1617], heights: [432, 227, 220, 227, 220, 220, 376], height: 2088 },
  animated: { height: 8.5 * SCREEN_PX + 95 },
};
const WINDOW_PX = 800;
function pageEnvironment(options) {
  const env = environment(options);
  const view = () => env.ids.story.classes.has("animated") ? "animated" : env.ids.story.classes.has("stills") ? "stills" : "text";
  env.copies.forEach((el, i) => {
    el.getBoundingClientRect = () => {
      const page = PAGES[view()];
      // In the animated story every copy fills the pinned stage.
      if (!page.tops) return { top: 0, bottom: WINDOW_PX, left: 0, right: 1280 };
      const top = page.tops[i] - env.win.scrollY;
      return { top, bottom: top + page.heights[i], left: 0, right: 1280 };
    };
  });
  env.win.scrollTo = ({ top }) => { env.win.scrollY = Math.max(0, Math.min(PAGES[view()].height - WINDOW_PX, top)); };
  env.doc.documentElement = { get scrollHeight() { return PAGES[view()].height; } };
  env.view = view;
  env.scrollTo = async (top) => { env.win.scrollTo({ top }); await env.win.dispatch("scroll"); };
  env.shown = () => env.copies.filter((el) => el.classes.has("on") && !el.inert).map((el) => el.dataset.copy);
  // Where a copy's block sits in the window in the still and text views.
  env.topOf = (copy) => env.copies.find((el) => el.dataset.copy === copy).getBoundingClientRect().top;
  return env;
}
const COPY_NAMES = ["hero", "alone", "swarm", "robot1", "robot2", "robot3", "end"];
// A scroll position, in screens, at which each copy is the one shown.
const SHOWN_AT = { hero: 0.3, alone: 1.6, swarm: 2.9, robot1: 4.0, robot2: 4.9, robot3: 5.7, end: 7.1 };

test("pausing and resuming returns the reader to the very place they paused at", async () => {
  for (const copy of COPY_NAMES) {
    const env = pageEnvironment();
    const toggle = env.ids["motion-toggle"];
    await env.scrollTo(SHOWN_AT[copy] * SCREEN_PX);
    assert.deepEqual(env.shown(), [copy]);
    await toggle.dispatch("click");
    assert.equal(env.view(), "stills");
    // The copy the reader was on is at the top of the still view, under the nav. The page is
    // too short to bring its last copy that high; it is then scrolled to its end.
    const atEnd = env.win.scrollY === PAGES.stills.height - WINDOW_PX;
    assert.ok(copy === "hero" ? env.win.scrollY === 0 : env.topOf(copy) === 88 || atEnd, `${copy} is brought to the top of the still view`);
    assert.equal(atEnd, copy === "end");
    await toggle.dispatch("click");
    assert.equal(env.view(), "animated");
    assert.equal(env.win.scrollY, SHOWN_AT[copy] * SCREEN_PX, `${copy}: resumed at the scroll position paused at`);
    assert.deepEqual(env.shown(), [copy], `${copy} is shown again`);
    assert.equal(railNow(env).step, STEP_OF[copy]);
  }
});

test("text only and back returns the reader to the same place, also where the text page is too short to show it on top", async () => {
  for (const copy of COPY_NAMES) {
    const env = pageEnvironment();
    const graphics = env.ids["graphics-toggle"];
    await env.scrollTo(SHOWN_AT[copy] * SCREEN_PX);
    await graphics.dispatch("click");
    assert.equal(env.view(), "text");
    // Three copies fit in the last window of the text page: "robot3" and "end" cannot reach the top.
    const atEnd = env.win.scrollY === PAGES.text.height - WINDOW_PX;
    assert.equal(atEnd, copy === "robot3" || copy === "end");
    await graphics.dispatch("click");
    assert.equal(env.view(), "animated");
    assert.equal(env.win.scrollY, SHOWN_AT[copy] * SCREEN_PX, `${copy}: back at the scroll position left`);
    assert.deepEqual(env.shown(), [copy]);
  }
});

test("a pause in a gap between two scenes resumes in that gap, not on a neighbouring scene", async () => {
  const env = pageEnvironment();
  await env.scrollTo(3.4 * SCREEN_PX);
  assert.deepEqual(env.shown(), []);
  await env.ids["motion-toggle"].dispatch("click");
  assert.equal(env.topOf("swarm"), 88, "the nearer scene is brought to the top of the still view");
  await env.ids["motion-toggle"].dispatch("click");
  assert.equal(env.win.scrollY, 3.4 * SCREEN_PX);
});

test("a reader who scrolled the still view resumes on the scene they scrolled to", async () => {
  // Each copy rests where the rail jumps to; the second and third robot lines rest mid-beat.
  const REST = { hero: 0, alone: 1.5, swarm: 2.75, robot1: 3.95, robot2: 4.875, robot3: 5.825, end: 7.02 };
  for (const copy of COPY_NAMES) {
    const env = pageEnvironment();
    const toggle = env.ids["motion-toggle"];
    await env.scrollTo(SHOWN_AT.alone * SCREEN_PX);
    await toggle.dispatch("click");
    // Scroll the still view until this copy is the first one whole in the window: its top a
    // little under the nav, or the end of the page for the last copy.
    await env.scrollTo(PAGES.stills.tops[COPY_NAMES.indexOf(copy)] - 150);
    await toggle.dispatch("click");
    assert.equal(env.view(), "animated");
    assert.deepEqual(env.shown(), [copy], `resumed on ${copy}`);
    assert.ok(Math.abs(env.win.scrollY - REST[copy] * SCREEN_PX) < 1, `${copy} is at rest: ${env.win.scrollY}`);
    // A second pause and resume without scrolling stays exactly there.
    const at = env.win.scrollY;
    await toggle.dispatch("click");
    await toggle.dispatch("click");
    assert.equal(env.win.scrollY, at);
  }
});

test("with reduced motion, text only and back keeps the copy the reader was on", async () => {
  const env = pageEnvironment();
  const reduced = env.queries.get("(prefers-reduced-motion: reduce)");
  reduced.matches = true;
  await reduced.dispatch("change");
  assert.equal(env.view(), "stills");
  const graphics = env.ids["graphics-toggle"];
  await env.scrollTo(1900);
  await graphics.dispatch("click");
  assert.equal(env.view(), "text");
  assert.equal(env.topOf("robot2"), 88, "the copy in view in the stills is on top of the text");
  await graphics.dispatch("click");
  assert.equal(env.view(), "stills");
  assert.equal(env.topOf("robot2"), 88);
  // Where the text page is too short to put the copy on top, the way back still finds it.
  await env.scrollTo(PAGES.stills.tops[5] - 100);
  await graphics.dispatch("click");
  assert.equal(env.win.scrollY, PAGES.text.height - WINDOW_PX);
  await graphics.dispatch("click");
  assert.equal(env.topOf("robot3"), 88);
  // At the top of the page nothing moves.
  await env.scrollTo(0);
  await graphics.dispatch("click");
  await graphics.dispatch("click");
  assert.equal(env.win.scrollY, 0);
});

test("a remembered place holds only while the reader has not scrolled and the window is the same", async () => {
  const env = pageEnvironment();
  const graphics = env.ids["graphics-toggle"];
  const left = SHOWN_AT.robot3 * SCREEN_PX;
  // Where "swarm" rests in the animated story: where a reader is put who is found on it by
  // looking at the page, without a remembered position.
  const rest = 2.75 * SCREEN_PX;
  // "robot3" cannot reach the top of the short text page; the page is scrolled to its end.
  await env.scrollTo(left);
  await graphics.dispatch("click");
  assert.equal(env.win.scrollY, PAGES.text.height - WINDOW_PX);
  await env.scrollTo(env.win.scrollY - 40);
  await env.scrollTo(env.win.scrollY + 40);
  await graphics.dispatch("click");
  assert.equal(env.win.scrollY, left, "scrolling away and back to the same spot is still the same place");
  // Scrolled up by 300, "robot2" and "robot3" are both whole in the window; the upper one counts.
  await graphics.dispatch("click");
  await env.scrollTo(env.win.scrollY - 300);
  await graphics.dispatch("click");
  assert.deepEqual(env.shown(), ["robot2"], "after a scroll the copy in view is the reader's place");
  // A window that changed size lays the page out anew, so the remembered offset means nothing.
  await env.scrollTo(SHOWN_AT.swarm * SCREEN_PX);
  await graphics.dispatch("click");
  assert.equal(env.topOf("swarm"), 88);
  env.context.innerWidth = 1000;
  await graphics.dispatch("click");
  assert.deepEqual(env.shown(), ["swarm"]);
  assert.ok(Math.abs(env.win.scrollY - rest) < 1, "after a resize the reader is put on the copy in view, at rest");
  // A setting changed outside the page presents the story anew without scrolling it. Back in
  // the same presentation at the same spot, the place still holds.
  const forced = env.queries.get("(forced-colors: active)");
  await env.scrollTo(SHOWN_AT.swarm * SCREEN_PX);
  await env.ids["motion-toggle"].dispatch("click");
  assert.equal(env.topOf("swarm"), 88);
  const paused = env.win.scrollY;
  forced.matches = true;
  await forced.dispatch("change");
  assert.equal(env.view(), "text");
  assert.equal(env.win.scrollY, paused, "a setting changed outside the page does not scroll it");
  forced.matches = false;
  await forced.dispatch("change");
  assert.equal(env.view(), "stills");
  await env.ids["motion-toggle"].dispatch("click");
  assert.equal(env.win.scrollY, SHOWN_AT.swarm * SCREEN_PX);
});

test("in the still and text views the reader's copy is the first one nearly whole under the nav", async () => {
  // The copy shown after a return to the animated story tells which copy the reader was taken to be on.
  const resumedFrom = async (kind, scrollY) => {
    const env = pageEnvironment();
    const toggle = env.ids[kind === "stills" ? "motion-toggle" : "graphics-toggle"];
    await toggle.dispatch("click");
    assert.equal(env.view(), kind);
    await env.scrollTo(scrollY);
    await toggle.dispatch("click");
    return env.shown();
  };
  // Several copies fit in a window of the text view. A copy 7px taller than its neighbours
  // does not win over the one above it, and the tall last copy does not win from below.
  assert.deepEqual(await resumedFrom("text", 581), ["swarm"]);
  assert.deepEqual(await resumedFrom("text", 1247), ["robot3"]);
  // At the end of the page the reader has reached the last copy, though "robot3" is still
  // whole at the top of that last window. At the top of the page they are on the first.
  assert.deepEqual(await resumedFrom("text", PAGES.text.height - WINDOW_PX), ["end"]);
  assert.deepEqual(await resumedFrom("stills", PAGES.stills.height - WINDOW_PX), ["end"]);
  assert.deepEqual(await resumedFrom("text", 0), ["hero"]);
  assert.deepEqual(await resumedFrom("stills", 0), ["hero"]);
  // A tall copy that is cut off a little by the nav still counts before a short one below it.
  assert.deepEqual(await resumedFrom("text", 40), ["hero"]);
  // No copy is four fifths in view here; the one with more of the window counts.
  assert.deepEqual(await resumedFrom("stills", 150), ["hero"]);
  assert.deepEqual(await resumedFrom("stills", 250), ["alone"]);
  // A copy put under the nav is still the reader's after a small scroll either way.
  for (const kind of ["stills", "text"]) {
    for (const nudge of [-40, 40]) {
      const env = pageEnvironment();
      const toggle = env.ids[kind === "stills" ? "motion-toggle" : "graphics-toggle"];
      await env.scrollTo(SHOWN_AT.swarm * SCREEN_PX);
      await toggle.dispatch("click");
      assert.equal(env.topOf("swarm"), 88);
      await env.scrollTo(env.win.scrollY + nudge);
      await toggle.dispatch("click");
      assert.deepEqual(env.shown(), ["swarm"], `${kind} view scrolled by ${nudge}`);
    }
  }
});
