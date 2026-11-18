"""A strict check of the ECMAScript RegExp grammar in unicode mode (the ``u`` flag), for tests.

JSON Schema ``pattern`` values are ECMA-262 regular expressions, and an MCP host that validates or
renders a tool's schema compiles them with a JavaScript engine, typically in unicode mode (ajv's
default). Unicode mode drops the web-compatibility grammar of Annex B, so text Python's ``re``
accepts can fail there (Cursor 3.27.22 dropped every FinishUP tool when one pattern escaped a
space as ``\\ ``). This module parses ``Pattern[+UnicodeMode, ~UnicodeSetsMode, +NamedCaptureGroups]``
and raises ``ECMAPatternError`` for what such an engine refuses:

- an escape that is not one of ``\\b \\B``, a decimal backreference to a group that exists,
  ``\\k<name>`` naming a group that exists, ``\\d \\D \\s \\S \\w \\W``, ``\\p{…}``/``\\P{…}``, the
  control escapes ``\\f \\n \\r \\t \\v``, ``\\cX``, ``\\0`` not followed by a digit, ``\\xHH``,
  ``\\uHHHH`` and ``\\u{H…}``, or a syntax character or ``/`` (and, in a class, ``\\-`` and
  ``\\b``): an identity escape of anything else (``\\ ``, ``\\_``, ``\\a``…) is refused;
- an unescaped syntax character where a literal is expected: a lone ``{``, ``}`` or ``]``, a
  quantifier with nothing to repeat, an unbalanced parenthesis;
- a quantifier ``{n,m}`` with ``n > m``, a quantified lookaround, a group kind other than
  ``(?:``, ``(?=``, ``(?!``, ``(?<=``, ``(?<!`` and ``(?<name>``, a duplicate or invalid group name;
- a class range whose end is a class escape (``[\\w-a]``) or that runs backwards.

What it does not check: whether a ``\\p{…}`` property name is one the engine knows; whether the
pattern means the same in Python and in ECMAScript (``$`` before a final newline,
``\\d``/``\\w``/``\\s`` on non-ASCII text, which differ between them); and the ``v`` flag's
stricter class grammar (``v`` is not what JSON Schema validators use, and the advertised schemas do
not follow it). It is stricter than a current engine, refusing what such an engine may accept:
ES2025 modifier groups (``(?i:…)``), duplicate group names in separate alternatives, and group
names outside ASCII or written with ``\\u`` escapes. A test that can run a real engine checks the
same patterns with it as well.
"""

from __future__ import annotations

import re
import string
from typing import Final

__all__ = ["ECMAPatternError", "check_unicode_pattern"]

_SYNTAX: Final = frozenset("^$\\.*+?()[]{}|")
_CONTROL: Final = {"f": 0x0C, "n": 0x0A, "r": 0x0D, "t": 0x09, "v": 0x0B}
_QUANTIFIER: Final = re.compile(r"\{([0-9]+)(?:(,)([0-9]*))?\}")
_GROUP_NAME: Final = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_PROPERTY: Final = re.compile(r"[A-Za-z0-9_]+(?:=[A-Za-z0-9_]+)?")
_CLASS: Final = object()  # a class escape (\d, \p{…}) as a class atom: never a range end


class ECMAPatternError(ValueError):
    """A pattern an ECMAScript engine refuses in unicode mode; the message says where."""


def check_unicode_pattern(pattern: str) -> None:
    """Raise ``ECMAPatternError`` when ``pattern`` is not a unicode-mode ECMAScript pattern."""

    _Parser(pattern).parse()


class _Parser:
    def __init__(self, source: str) -> None:
        self.source = source
        self.at = 0
        self.groups = 0
        self.names: set[str] = set()
        self.backreferences: list[int] = []
        self.named_references: list[str] = []

    # --- helpers -----------------------------------------------------------------------------------

    def fail(self, why: str) -> ECMAPatternError:
        return ECMAPatternError(f"{why} at {self.at}")

    def peek(self, ahead: int = 0) -> str | None:
        index = self.at + ahead
        return self.source[index] if index < len(self.source) else None

    def starts(self, text: str) -> bool:
        return self.source.startswith(text, self.at)

    def expect(self, text: str) -> None:
        if not self.starts(text):
            raise self.fail(f"expected {text!r}")
        self.at += len(text)

    # --- the grammar -------------------------------------------------------------------------------

    def parse(self) -> None:
        self.disjunction()
        if self.at != len(self.source):
            raise self.fail("unbalanced ')'")
        for number in self.backreferences:
            if number > self.groups:
                raise ECMAPatternError(f"backreference \\{number} to a group that does not exist")
        for name in self.named_references:
            if name not in self.names:
                raise ECMAPatternError(f"\\k<{name}> names no group")

    def disjunction(self) -> None:
        self.alternative()
        while self.peek() == "|":
            self.at += 1
            self.alternative()

    def alternative(self) -> None:
        while self.peek() not in {None, "|", ")"}:
            self.term()

    def term(self) -> None:
        if self.peek() in {"^", "$"}:
            self.at += 1
            return
        if self.starts("\\b") or self.starts("\\B"):
            self.at += 2
            return
        for lookaround in ("(?=", "(?!", "(?<=", "(?<!"):
            if self.starts(lookaround):
                self.at += len(lookaround)
                self.disjunction()
                self.expect(")")
                if self.peek() in {"*", "+", "?", "{"}:
                    raise self.fail("a lookaround cannot be quantified")
                return
        self.atom()
        self.quantifier()

    def quantifier(self) -> None:
        mark = self.peek()
        if mark in {"*", "+", "?"}:
            self.at += 1
        elif mark == "{":
            found = _QUANTIFIER.match(self.source, self.at)
            if found is None:
                raise self.fail("lone '{'")
            low, comma, high = found.group(1), found.group(2), found.group(3)
            if comma and high and int(low) > int(high):
                raise self.fail("quantifier range out of order")
            self.at = found.end()
        else:
            return
        if self.peek() == "?":
            self.at += 1
        if self.peek() in {"*", "+", "?", "{"}:
            raise self.fail("nothing to repeat")

    def atom(self) -> None:
        mark = self.peek()
        if mark == ".":
            self.at += 1
        elif mark == "(":
            self.group()
        elif mark == "[":
            self.character_class()
        elif mark == "\\":
            self.at += 1
            self.atom_escape()
        elif mark is None or mark in _SYNTAX:
            raise self.fail(f"syntax character {mark!r} needs an escape or has nothing to repeat")
        else:
            self.at += 1

    def group(self) -> None:
        if self.starts("(?:"):
            self.at += 3
        elif self.starts("(?<"):
            self.at += 3
            name = self.group_name()
            if name in self.names:
                raise self.fail(f"duplicate group name {name!r}")
            self.names.add(name)
            self.groups += 1
        elif self.starts("(?"):
            raise self.fail("unknown group kind")
        else:
            self.at += 1
            self.groups += 1
        self.disjunction()
        self.expect(")")

    def group_name(self) -> str:
        found = _GROUP_NAME.match(self.source, self.at)
        if found is None:
            raise self.fail("invalid group name")
        self.at = found.end()
        self.expect(">")
        return found.group(0)

    def atom_escape(self) -> None:
        mark = self.peek()
        if mark is not None and mark in "123456789":
            digits = re.match(r"[0-9]+", self.source[self.at :])
            assert digits is not None
            self.backreferences.append(int(digits.group(0)))
            self.at += len(digits.group(0))
            return
        if mark == "k":
            self.at += 1
            self.expect("<")
            self.named_references.append(self.group_name())
            return
        self.escape(in_class=False)

    def escape(self, *, in_class: bool) -> int | object:
        """One escape after its backslash: its code point, or ``_CLASS`` for a class escape."""

        mark = self.peek()
        if mark is None:
            raise self.fail("trailing backslash")
        self.at += 1
        if mark in "dDsSwW":
            return _CLASS
        if mark in "pP":
            self.expect("{")
            found = _PROPERTY.match(self.source, self.at)
            if found is None:
                raise self.fail("invalid property escape")
            self.at = found.end()
            self.expect("}")
            return _CLASS
        if mark in _CONTROL:
            return _CONTROL[mark]
        if mark == "c":
            letter = self.peek()
            if letter is None or letter not in string.ascii_letters:
                raise self.fail("\\c needs an ASCII letter")
            self.at += 1
            return ord(letter) % 32
        if mark == "0":
            if (self.peek() or "") in "0123456789" and self.peek() is not None:
                raise self.fail("octal escapes are refused")
            return 0
        if mark == "x":
            return self.hex_digits(2)
        if mark == "u":
            return self.unicode_escape()
        if mark in _SYNTAX or mark == "/":
            return ord(mark)
        if in_class and mark == "-":
            return ord("-")
        if in_class and mark == "b":
            return 0x08
        raise self.fail(f"identity escape \\{mark} is refused in unicode mode")

    def hex_digits(self, count: int) -> int:
        text = self.source[self.at : self.at + count]
        if len(text) != count or re.fullmatch(r"[0-9A-Fa-f]+", text) is None:
            raise self.fail("invalid hexadecimal escape")
        self.at += count
        return int(text, 16)

    def unicode_escape(self) -> int:
        if self.peek() == "{":
            found = re.match(r"\{([0-9A-Fa-f]+)\}", self.source[self.at :])
            if found is None or int(found.group(1), 16) > 0x10FFFF:
                raise self.fail("invalid \\u{…} escape")
            self.at += found.end()
            return int(found.group(1), 16)
        value = self.hex_digits(4)
        if 0xD800 <= value <= 0xDBFF and self.starts("\\u"):
            trail = re.fullmatch(r"[0-9A-Fa-f]{4}", self.source[self.at + 2 : self.at + 6])
            if trail is not None and 0xDC00 <= int(trail.group(0), 16) <= 0xDFFF:
                self.at += 6
                return 0x10000 + ((value - 0xD800) << 10) + (int(trail.group(0), 16) - 0xDC00)
        return value

    def character_class(self) -> None:
        self.expect("[")
        if self.peek() == "^":
            self.at += 1
        while self.peek() != "]":
            if self.peek() is None:
                raise self.fail("unterminated class")
            start = self.class_atom()
            if self.peek() == "-" and self.peek(1) not in {None, "]"}:
                self.at += 1
                end = self.class_atom()
                if start is _CLASS or end is _CLASS:
                    raise self.fail("a class escape cannot end a range")
                assert isinstance(start, int) and isinstance(end, int)
                if start > end:
                    raise self.fail("class range out of order")
        self.at += 1

    def class_atom(self) -> int | object:
        mark = self.peek()
        assert mark is not None
        self.at += 1
        if mark != "\\":
            return ord(mark)
        if (self.peek() or "") in "123456789" and self.peek() is not None:
            raise self.fail("a backreference cannot appear in a class")
        return self.escape(in_class=True)
