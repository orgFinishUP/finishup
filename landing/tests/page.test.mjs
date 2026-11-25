import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
const page = readFileSync(new URL("../src/pages/index.astro", import.meta.url), "utf8");

test("the landing page does not publish the placeholder benchmark scene", () => {
  assert.doesNotMatch(page, /Terminal-Bench 4|data-copy="bench"|bench-scores|\[PAPER URL\]/);
  assert.doesNotMatch(page, /\["sun", 3\]/);
});

test("forced colours get the static story", () => {
  // In forced colours the artwork's dots carry no reliable contrast, so the page takes the
  // same static presentation as reduced motion, and follows the setting when it changes.
  assert.match(page, /const forced = window\.matchMedia\("\(forced-colors: active\)"\);/);
  assert.match(page, /const canAnimate = [^;]*!forced\.matches[^;]*;/, "forced colours turn the animated story off");
  assert.match(page, /forced\.addEventListener\("change", syncPresentation\);/, "a change of the setting re-presents the story");
});

// The page's markup, without the head and the script: what a reader tabs through.
const body = page.slice(page.indexOf("<body"), page.indexOf("<script>"));
const css = readFileSync(new URL("../src/styles/landing.css", import.meta.url), "utf8");
// Every link and button of the page in source order, which is the order Tab visits them in:
// nothing on the page sets a tabindex above zero.
const tabStops = Array.from(body.matchAll(/<(?:a|button)\b[^>]*>/g), (m) => m[0]);
const idOf = (tag) => tag.match(/\bid="([^"]*)"/)?.[1];

// The opening tag of the element with this id, where it starts, and a reader for its attributes.
function element(id) {
  const m = body.match(new RegExp(`<[a-z]+\\b[^>]*\\bid="${id}"[^>]*>`));
  assert.ok(m, `#${id} is in the page`);
  return {
    at: m.index,
    has: (name) => new RegExp(`\\s${name}(?=[\\s=>])`).test(m[0]),
    attr: (name) => m[0].match(new RegExp(`\\s${name}="([^"]*)"`))?.[1],
  };
}

test("the accessibility menu is the first Tab stop after the skip link", () => {
  // The menu holds the only control that pauses the artwork. It was a button in the top nav,
  // ahead of the story; it stays ahead of the nav and the story wherever CSS draws it.
  assert.doesNotMatch(body, /\btabindex="[1-9]/, "source order is Tab order");
  assert.match(tabStops[0], /class="skip-link"/);
  assert.equal(idOf(tabStops[1]), "a11y-trigger", "the menu's trigger follows the skip link");
  const trigger = element("a11y-trigger");
  assert.ok(trigger.at < body.indexOf("<header"), "the trigger comes before the nav");
  assert.ok(trigger.at < body.indexOf("<main"), "the trigger comes before the story");
});

test("the accessibility panel follows its trigger, so Tab goes from the trigger into it", () => {
  const menu = element("a11y-menu");
  const trigger = element("a11y-trigger");
  const panel = element("a11y-panel");
  const menuEnd = body.indexOf("</aside>", menu.at);
  assert.ok(menu.at < trigger.at && trigger.at < panel.at && panel.at < menuEnd, "trigger, then panel, both in the menu");
  assert.deepEqual(tabStops.slice(1, 5).map(idOf), ["a11y-trigger", "a11y-close", "motion-toggle", "graphics-toggle"]);
  assert.equal(trigger.attr("aria-controls"), "a11y-panel");
  assert.equal(trigger.attr("aria-expanded"), "false", "the panel starts closed");
  assert.ok(panel.has("hidden"), "the panel starts closed");
  // The panel is still drawn above the trigger, as designed: the menu is anchored by its
  // bottom edge and stacks its children upwards.
  const rule = css.match(/\.a11y-menu \{[^}]*\}/)?.[0] ?? "";
  assert.match(rule, /position: fixed;/);
  assert.match(rule, /flex-direction: column-reverse;/);
});

test("each switch keeps one name, its visible label, and says its state with aria-checked alone", () => {
  // A switch is announced as its name plus on or off. A name that changes with the state
  // ("Pause animation" off, "Play animation" on) reads as the opposite of what the switch shows.
  for (const [id, label] of [["motion-toggle", "Pause motion"], ["graphics-toggle", "Text only"]]) {
    const toggle = element(id);
    assert.equal(toggle.attr("role"), "switch");
    assert.equal(toggle.attr("aria-checked"), "false");
    assert.equal(toggle.attr("aria-label"), undefined, `#${id} is named by its visible label, not by a second wording`);
    const name = element(toggle.attr("aria-labelledby"));
    assert.equal(name.attr("class"), "a11y-name", "the name is the label drawn beside the switch");
    assert.equal(body.slice(name.at).match(/>([^<]*)</)[1], label);
    assert.equal(element(toggle.attr("aria-describedby")).attr("class"), "a11y-desc");
  }
  const script = page.slice(page.indexOf("<script>"));
  assert.doesNotMatch(script, /setAttribute\("aria-label(?:ledby)?"/, "the page script never renames a control");
});
