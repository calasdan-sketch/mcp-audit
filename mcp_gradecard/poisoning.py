"""Look for prompt injection in what a server says about its tools.

An MCP server describes each of its tools in free text, and the agent reads
that text as if it were part of its own instructions. A hostile server (or a
hijacked update of a good one) can use it to steer the agent - "tool
poisoning": read a private key, hand it over in an argument, say nothing to
the user. `scan` looks for the ways that is done.

It is a tripwire, not a proof. A text it passes may still be hostile (a
paraphrase, a language it does not know, an instruction that only makes sense
next to another tool), and one it flags may be innocent (a security scanner
that describes the very attack). What it returns says which signals it found
and why they add up to the severity it gives; the text itself is never
repeated, because a report can be read by an agent too.

How a text is read:

1. Hidden characters (zero-width and tag characters, bidirectional controls,
   variation-selector runs, control characters ...) are counted and reported.
   Ordinary uses are left alone: the joiners of an emoji sequence or of a
   script that needs them, a selector after a symbol, the controls that go
   with right-to-left text.
2. The text is normalised into the form a reader would see: hidden characters
   removed, Unicode compatibility forms folded (full-width letters, styled
   letters), accents dropped, look-alike letters of other scripts folded onto
   Latin ones, case and white space collapsed. Text the reader cannot see, or
   sees reversed, and text that is encoded (base64, hex, percent, HTML
   entities, backslash escapes) is decoded, two levels deep, and read the
   same way. Every encoded run is decoded however many there are, so that a
   payload cannot hide behind padding; at most MAX_TEXT characters of the
   result are read, and what is left over is reported, not passed.
3. Each reading is searched for signals: an override of the agent's
   instructions, concealment from the user, a sensitive file the agent is told
   to read (or whose contents a parameter is to hold), a way of passing data
   along (a tool argument, a URL), a fake system tag, a claim of priority over
   the user. A refusal is not an order: "does not read ~/.git-credentials" and
   "Vergessen Sie nicht, die vorherigen Anweisungen zu lesen" are no signal.
4. A signal on its own is a lead (low or medium). Only combinations are high
   or critical: concealment plus anything else, a sensitive file plus a way
   to pass it on, hidden text plus a payload. A plain override of the agent's
   instructions ("ignore previous instructions") is critical on its own.

Every pattern is bounded (no unbounded repetition of a group, no quantified
alternation over the text), and a text is cut at MAX_TEXT characters, so the
time is linear in the size of what a hostile server sends.
"""

from __future__ import annotations

import base64
import bisect
import html
import itertools
import json
import re
import unicodedata
import urllib.parse
from typing import NamedTuple

#: Characters of one text that are read. A description is a paragraph; one
#: longer than this is reported as such, not scanned to its end.
MAX_TEXT = 100_000
_MAX_DECODED = MAX_TEXT  # characters of decoded text read for one text
_MAX_MARKS = 16         # combining marks kept in a row (see _cap_marks)
_BACKSLASH = chr(92)


class Verdict(NamedTuple):
    severity: str                # critical, high, medium or low
    signals: tuple               # the codes of the signals found
    labels: tuple                # fixed phrases, never text of the description


# --- hidden characters ----------------------------------------------------

def _esc(cp: int) -> str:
    """A character, spelled for use inside a regular expression."""
    return _BACKSLASH + ("u%04x" % cp if cp <= 0xFFFF else "U%08x" % cp)


def _charclass(ranges) -> str:
    return "[" + "".join(_esc(a) if a == b else _esc(a) + "-" + _esc(b)
                         for a, b in ranges) + "]"


# (first, last, kind) of the characters that show nothing, or something other
# than what they are, and so have no business in a description.
_HIDDEN = (
    (0x00, 0x08, "control"), (0x0E, 0x1F, "control"),
    (0x7F, 0x84, "control"), (0x86, 0x9F, "control"),
    (0xAD, 0xAD, "invisible"), (0x34F, 0x34F, "invisible"),
    (0x61C, 0x61C, "bidirectional"),
    (0x115F, 0x1160, "invisible"), (0x17B4, 0x17B5, "invisible"),
    (0x180E, 0x180E, "invisible"),
    (0x200B, 0x200D, "zero-width"), (0x200E, 0x200F, "bidirectional"),
    (0x202A, 0x202C, "bidirectional"),
    (0x202D, 0x202E, "bidirectional override"),
    (0x2060, 0x2060, "zero-width"), (0x2061, 0x2064, "invisible"),
    (0x2066, 0x2069, "bidirectional"), (0x206A, 0x206F, "invisible"),
    (0x2800, 0x2800, "invisible"), (0x3164, 0x3164, "invisible"),
    (0xFEFF, 0xFEFF, "zero-width"), (0xFFA0, 0xFFA0, "invisible"),
    (0xFFF9, 0xFFFB, "invisible"),
)
_SELECTORS = ((0x180B, 0x180D), (0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
_TAGS = (0xE0000, 0xE007F)
_KIND = {cp: kind for first, last, kind in _HIDDEN
         for cp in range(first, last + 1)}
_ODD_RE = re.compile(_charclass([(a, b) for a, b, _k in _HIDDEN]))
_TAG_RE = re.compile(_charclass([_TAGS]) + "+")
_SELECTOR_RE = re.compile(_charclass(_SELECTORS) + "+")
_RTL_RE = re.compile(_charclass([(0x590, 0x8FF), (0xFB1D, 0xFDFF),
                                 (0xFE70, 0xFEFE), (0x10800, 0x10FFF),
                                 (0x1E800, 0x1EFFF)]))
_RLO_RE = re.compile(_esc(0x202E) + "([^" + _esc(0x202C) + "]*)")
_GONE = [cp for cp in _KIND] + [cp for a, b in _SELECTORS
                                for cp in range(a, b + 1)] + list(
    range(_TAGS[0], _TAGS[1] + 1))
_REMOVE = {cp: None for cp in _GONE}
_SPACE_OUT = {cp: " " for cp in _GONE}
#: The only tag sequences that mean something: England, Scotland, Wales.
_FLAG_TAGS = ("gbeng" + chr(0x7F), "gbsct" + chr(0x7F), "gbwls" + chr(0x7F))
_WAVING_FLAG = chr(0x1F3F4)
_ZWJ, _ZWNJ, _ZWSP, _WJ = (chr(0x200D), chr(0x200C), chr(0x200B),
                           chr(0x2060))
_KEYCAP = chr(0x20E3)


class _Hidden(NamedTuple):
    kinds: dict                  # kind -> how many
    tag_text: str                # what the tag characters spell
    reversed: list              # the text a right-to-left override reverses

    @property
    def count(self) -> int:
        return sum(self.kinds.values())


def _category(ch: str) -> str:
    return unicodedata.category(ch)[0] if ch else ""


def _is_ideograph(ch: str) -> bool:
    cp = ord(ch)
    return (0x2E80 <= cp <= 0x9FFF or 0xF900 <= cp <= 0xFAFF
            or 0x20000 <= cp <= 0x3FFFF)


def _selector_is_ordinary(text: str, start: int, run: str) -> bool:
    """One variation selector after something it can vary: an emoji, a
    symbol, an ideograph, or the digit of a keycap."""
    if len(run) != 1 or not start:
        return False
    before, after = text[start - 1], text[start + 1:start + 2]
    if ord(run) >= 0xE0100:
        return _is_ideograph(before)
    if before in "0123456789#*":
        return after == _KEYCAP
    return ord(before) > 0x7F and _category(before) in ("L", "M", "N", "S")


def _joins(text: str, i: int, categories: str) -> bool:
    """True when the character at `i` sits between two characters of a
    script that is not ASCII (an emoji sequence, a conjunct, Persian,
    Thai ...), where it does work."""
    if not i:
        return False
    before, after = text[i - 1], text[i + 1:i + 2]
    return (bool(after) and ord(before) > 0x7F and ord(after) > 0x7F
            and _category(before) in categories
            and _category(after) in categories)


def _cap_marks(text: str):
    """(text without the combining marks beyond _MAX_MARKS in a row, how many
    were dropped). unicodedata.normalize is quadratic in the length of such a
    run on Python 3.10 (80,000 marks took 23 seconds), and a run that long is
    not text."""
    if text.isascii():
        return text, 0
    out, run, dropped = [], 0, 0
    combining = unicodedata.combining
    for ch in text:
        if combining(ch):
            run += 1
            if run > _MAX_MARKS:
                dropped += 1
                continue
        else:
            run = 0
        out.append(ch)
    return ("".join(out) if dropped else text), dropped


def _hidden(text: str) -> _Hidden:
    kinds: dict = {}

    def flag(kind: str, n: int = 1) -> None:
        kinds[kind] = kinds.get(kind, 0) + n

    spelled = []
    for m in _TAG_RE.finditer(text):
        run = m.group()
        decoded = "".join(chr(ord(c) - 0xE0000) for c in run)
        if (m.start() and text[m.start() - 1] == _WAVING_FLAG
                and decoded in _FLAG_TAGS):
            continue
        flag("tag", len(run))
        spelled.append("".join(c for c in decoded if " " <= c <= "~"))
    for m in _SELECTOR_RE.finditer(text):
        if not _selector_is_ordinary(text, m.start(), m.group()):
            flag("variation selector", len(m.group()))
    rtl = _RTL_RE.search(text) is not None
    for m in _ODD_RE.finditer(text):
        ch, kind = m.group(), _KIND[ord(m.group())]
        if kind == "bidirectional" and rtl:
            continue                     # the marks that go with Arabic, Hebrew
        if ch in (_ZWJ, _ZWNJ) and _joins(text, m.start(), "LMNS"):
            continue
        if ch in (_ZWSP, _WJ) and _joins(text, m.start(), "LM"):
            continue                     # a word break in Thai, Khmer ...
        flag(kind)
    _capped, dropped = _cap_marks(text)
    if dropped:
        flag("combining marks", dropped)
    return _Hidden(kinds, "".join(spelled),
                   [m.group(1) for m in _RLO_RE.finditer(text)])


# --- normalising ----------------------------------------------------------

# (code point, the Latin letter it is taken for) - lower case; the text is
# lower-cased first
_LOOKALIKES = (
    # Cyrillic
    (0x430, "a"), (0x432, "b"), (0x435, "e"), (0x43A, "k"), (0x43C, "m"),
    (0x43D, "h"), (0x43E, "o"), (0x440, "p"), (0x441, "c"), (0x442, "t"),
    (0x443, "y"), (0x445, "x"), (0x44C, "b"), (0x455, "s"), (0x456, "i"),
    (0x458, "j"), (0x4BB, "h"), (0x4CF, "l"), (0x501, "d"), (0x51B, "q"),
    (0x51D, "w"),
    # Greek
    (0x3B1, "a"), (0x3B3, "y"), (0x3B5, "e"), (0x3B7, "n"), (0x3B9, "i"),
    (0x3BA, "k"), (0x3BD, "v"), (0x3BF, "o"), (0x3C1, "p"), (0x3C4, "t"),
    (0x3C5, "u"), (0x3C7, "x"), (0x3C9, "w"), (0x3F2, "c"), (0x3F3, "j"),
    # Armenian
    (0x570, "h"), (0x578, "n"), (0x57D, "u"), (0x581, "g"), (0x585, "o"),
    # other Latin letters that are not the Latin letter
    (0x131, "i"), (0x251, "a"), (0x261, "g"), (0x269, "i"),
    # small capitals
    (0x1D00, "a"), (0x299, "b"), (0x1D04, "c"), (0x1D05, "d"),
    (0x1D07, "e"), (0xA730, "f"), (0x262, "g"), (0x29C, "h"), (0x26A, "i"),
    (0x1D0A, "j"), (0x1D0B, "k"), (0x29F, "l"), (0x1D0D, "m"),
    (0x274, "n"), (0x1D0F, "o"), (0x1D18, "p"), (0x280, "r"),
    (0xA731, "s"), (0x1D1B, "t"), (0x1D1C, "u"), (0x1D20, "v"),
    (0x1D21, "w"), (0x28F, "y"), (0x1D22, "z"),
    # quotation marks and dashes
    (0x2018, "'"), (0x2019, "'"), (0x201A, "'"), (0x201B, "'"),
    (0x201C, '"'), (0x201D, '"'), (0x201E, '"'), (0x201F, '"'),
    (0x2010, "-"), (0x2011, "-"), (0x2012, "-"), (0x2013, "-"),
    (0x2014, "-"), (0x2015, "-"), (0x2212, "-"),
)
_CONFUSABLES = {cp: letter for cp, letter in _LOOKALIKES}
_SPACES = re.compile(r"\s+")
_SQUASH = re.compile(r"[^a-z0-9]+")


def _fold(text: str) -> str:
    """`text` as a reader would see it, spelled one way: compatibility forms
    and accents folded, look-alike letters made Latin, lower case, single
    spaces."""
    if text.isascii():
        text = text.lower()
    else:
        text, _dropped = _cap_marks(text)
        text = unicodedata.normalize("NFKD", text).lower()
        text = "".join(ch for ch in text if not unicodedata.combining(ch))
        text = text.translate(_CONFUSABLES)
    return _SPACES.sub(" ", text).strip()


def _fold_raw(text: str) -> str:
    """Like _fold, but the scripts are left as they are (for patterns in
    Russian and Chinese)."""
    text, _dropped = _cap_marks(text)
    return _SPACES.sub(" ", unicodedata.normalize("NFKC", text).lower()
                       ).strip()


# --- encoded text ---------------------------------------------------------

_B64_RE = re.compile(r"[A-Za-z0-9+/_\-]{24,}")
_B64_PART_RE = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_LINE_BREAK = re.compile(r"[ \t\r\n]{1,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")
_ESCAPE_RE = re.compile(_BACKSLASH * 2 + "u([0-9a-fA-F]{4})|" + _BACKSLASH * 2
                        + "x([0-9a-fA-F]{2})")


def _text_of(raw: bytes):
    """`raw` as text if it is text (UTF-8, almost all printable)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 8:
        return None
    if text.isprintable():
        return text
    # text a reader cannot see (zero-width, tag characters ...) is text too;
    # control characters, which is what binary data decodes to, are not
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t"
               or _KIND.get(ord(ch), "control") != "control"
               or _TAGS[0] <= ord(ch) <= _TAGS[1])
    return text if good >= 0.9 * len(text) else None


def _from_base64(run: str):
    run = run.replace("-", "+").replace("_", "/")
    for skip in range(4):                # a letter or two glued in front
        chunk = run[skip:]
        if len(chunk) % 4 == 1:
            chunk = chunk[:-1]
        chunk += "=" * (-len(chunk) % 4)
        try:
            raw = base64.b64decode(chunk, validate=True)
        except ValueError:
            continue
        text = _text_of(raw)
        if text is not None:
            return text
    return None


def _unescape(match) -> str:
    return chr(int(match.group(1) or match.group(2), 16))


def _wrapped(text: str):
    """Base64 broken over lines (as mail does): consecutive runs with only a
    line break or a space between them, joined."""
    group, end = [], -1
    for m in _B64_PART_RE.finditer(text):
        if group and _LINE_BREAK.fullmatch(text, end, m.start()):
            group.append(m.group())
        else:
            if len(group) > 1:
                yield "".join(group)
            group = [m.group()]
        end = m.end()
    if len(group) > 1:
        yield "".join(group)


def _decodings(text: str) -> list:
    """(kind, decoded text) for what `text` holds in an encoding a reader
    could undo: base64, hex, percent escapes, HTML entities, \\u escapes.
    Every run is decoded, however many there are: a payload must not be able
    to hide behind padding. (The work is linear in the text; what is read of
    the result is capped in `scan`.)"""
    found = []
    for run in itertools.chain((m.group() for m in _B64_RE.finditer(text)),
                               _wrapped(text)):
        decoded = _from_base64(run)
        if decoded is not None:
            found.append(("base64", decoded))
    for m in _HEX_RE.finditer(text):
        try:
            decoded = _text_of(bytes.fromhex(m.group()))
        except ValueError:
            continue
        if decoded is not None:
            found.append(("hex", decoded))
    if text.count("%") >= 4:
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            found.append(("percent", decoded))
    if "&" in text and ";" in text:
        decoded = html.unescape(text)
        if decoded != text:
            found.append(("entities", decoded))
    if _BACKSLASH in text:
        decoded = _ESCAPE_RE.sub(_unescape, text)
        if decoded != text:
            found.append(("escapes", decoded))
    return found


def _is_json(text: str) -> bool:
    """A decoded JWT segment or a JSON example is data, not a message."""
    try:
        json.loads(text)
    except Exception:           # bad JSON, or nested too deeply
        return False
    return True


# --- signals --------------------------------------------------------------

_W = r"[^ ]{1,24}"                                   # one word


def _gap(low: int, high: int) -> str:
    """Between `low` and `high` words, each led by a space."""
    return "(?: %s){%d,%d}" % (_W, low, high)


def _words(*alternatives: str) -> str:
    return "(?:" + "|".join(alternatives) + ")"


# override of the agent's instructions
_FILL = _words("all", "any", "every", "each", "the", "these", "those", "of",
               "your", "my", "our", "what", "you", "were", "was", "have",
               "has", "had", "been", "are", "is", "told", "said", "given",
               "gave", "and", "other", "then", "that", "which", "came",
               "here", "before", "ever", "i", "me")
_ADJ = _words("previous", "prior", "above", "earlier", "preceding", "former",
              "original", "initial", "existing", "system", "developer",
              "safety", "security", "past", "foregoing", "your", "current",
              "given")
_NOUN = _words("instructions?", "prompts?", "rules", "guidelines",
               "directions", "directives", "commands", "constraints",
               "restrictions", "policies", "programming", "orders")
_FORGET = _words("ignor(?:e|ing)", "disregard(?:ing)?", "forget(?:ting)?",
                 "discard(?:ing)?", "neglect(?:ing)?", "abandon(?:ing)?")
_O_PLAIN = (
    re.compile(r"\b%s (?:%s ){0,4}%s(?: (?:%s|%s)){0,3} %s\b"
               % (_FORGET, _FILL, _ADJ, _FILL, _ADJ, _NOUN)),
    re.compile(r"\b%s (?:everything|anything|all|what) (?:above|before|that "
               r"came before|you were told|you have been told|you know|i "
               r"said|i told you|previously|said before)\b" % _FORGET),
    re.compile(r"\b%s (?:(?:all|any|the|everything) )?(?:above|preceding|"
               r"foregoing)\b" % _FORGET),
    re.compile(r"\b(?:overrid(?:e|ing)|overrul(?:e|ing)) (?:%s ){0,3}"
               r"(?:your|previous|prior|original|system|developer|safety)"
               r"(?: (?:%s|system|developer|safety|previous|prior|original))"
               r"{0,3} %s\b" % (_FILL, _FILL, _NOUN)),
    re.compile(r"\b(?:do not|don't|dont|never|stop) (?:follow|following|"
               r"obey|obeying|heed|heeding|listen to|listening to) "
               r"(?:(?:the|your|any|all|these|those) )*(?:previous|prior|"
               r"above|original|system|developer|your) %s\b" % _NOUN),
)
_NEGATED = re.compile(r"(?:\bnot|\bnever|n't|\bcannot|\bwithout|\bavoid|\bnor"
                      r"|\bno need to|\bstop) (?:\w+ )?$")
_O_SQUASHED = re.compile(r"(?:ignor(?:e|ing)|disregard(?:ing)?|forget"
                         r"(?:ting)?|discard(?:ing)?|neglect(?:ing)?|"
                         r"abandon(?:ing)?)(?:%s){0,6}%s(?:%s|%s){0,5}%s"
                         % (_FILL, _ADJ, _FILL, _ADJ, _NOUN))
_O_FOREIGN = (
    # French
    re.compile(r"\b(?:ignor(?:e|ez|er)|oubli(?:e|ez|er)|neglig(?:e|ez|er)|"
               r"ne tenez pas compte|ne tiens pas compte)\b%s (?:instructions?"
               r"|consignes?|directives?|regles?|ordres?)%s (?:precedent\w*|"
               r"anterieur\w*|ci-dessus|ci dessus|initial\w*)"
               % (_gap(0, 4), _gap(0, 2))),
    # Spanish, Portuguese, Italian
    re.compile(r"\b(?:ignor(?:a|e|en|ar|ad)|olvid(?:a|e|ar)|descart(?:a|e|ar)"
               r")\b%s (?:instrucciones|indicaciones|ordenes|reglas|"
               r"instrucoes|regras|orientacoes|istruzioni|ordini|regole)%s "
               r"(?:anteriores|previas|previos|precedentes|iniciales|acima|"
               r"prece\w*)" % (_gap(0, 4), _gap(0, 2))),
    # German
    re.compile(r"\b(?:ignorier\w*|vergiss|vergessen|missachte\w*|"
               r"ubergehe\w*)\b%s (?:vorherigen|fruheren|obigen|bisherigen|"
               r"vorigen|vorangegangenen|allen)%s (?:anweisungen|"
               r"instruktionen|vorgaben|regeln|befehle)"
               % (_gap(0, 4), _gap(0, 2))),
)
#: "nicht", "pas" ...: the order is refused ("Vergessen Sie nicht, die
#: vorherigen Anweisungen ...", "N'ignorez pas les instructions ..."). Inside
#: the words of the order, right before it (Spanish, Portuguese, Italian: "No
#: ignores ...") or, in German, right after it ("... Anweisungen nicht.") -
#: and not "sans hesiter" or "ohne Zogern", which refuse nothing.
_O_FOREIGN_NO = re.compile(r"\b(?:nicht|nie|niemals|kein\w*|pas|jamais|nunca|"
                           r"jamas|nao|no|non)\b")
_O_FOREIGN_NO_BEFORE = re.compile(r"(?:\bn'|\b(?:nicht|nie|niemals|no|non|"
                                  r"nao|nunca|jamais|jamas) )$")
_O_FOREIGN_NO_AFTER = re.compile(r" (?:nicht|nie|niemals)\b")
_O_NON_LATIN = (
    # Russian: ignore / forget ... previous ... instructions / rules
    re.compile(r"(?:\u0438\u0433\u043d\u043e\u0440\u0438\u0440|"
               r"\u0437\u0430\u0431\u0443\u0434\u044c)\w*(?: \w+){0,3} "
               r"(?:\u043f\u0440\u0435\u0434\u044b\u0434\u0443\u0449|"
               r"\u043f\u0440\u0435\u0436\u043d|\u043f\u0440\u043e\u0448\u043b)"
               r"\w*(?: \w+){0,2} (?:\u0438\u043d\u0441\u0442\u0440\u0443"
               r"\u043a\u0446\u0438|\u0443\u043a\u0430\u0437\u0430\u043d\u0438|"
               r"\u043f\u0440\u0430\u0432\u0438\u043b|\u043a\u043e\u043c\u0430"
               r"\u043d\u0434)\w*"),
    # Chinese: ignore the previous / all instructions
    re.compile(r"(?:\u5ffd\u7565|\u65e0\u89c6|\u5ffd\u89c6|\u4e0d\u8981"
               r"\u7406\u4f1a)(?:\u4e4b\u524d|\u5148\u524d|\u4ee5\u524d|"
               r"\u4ee5\u4e0a|\u4e0a\u9762|\u4e0a\u8ff0|\u524d\u9762|"
               r"\u6240\u6709|\u5168\u90e8|\u4efb\u4f55)(?:\u7684)?(?:\u6240"
               r"\u6709|\u5168\u90e8)?(?:\u6307\u4ee4|\u6307\u793a|\u8bf4"
               r"\u660e|\u63d0\u793a|\u89c4\u5219|\u547d\u4ee4|\u8981\u6c42)"),
)

# concealment from the user
_NOT = _words("do not", "don't", "dont", "never", "must not", "mustn't",
              "should not", "shouldn't", "cannot", "can't", "avoid",
              "refrain from", "without")
_TELL = _words("tell(?:ing)?", "inform(?:ing)?", "notify(?:ing)?",
               "alert(?:ing)?", "warn(?:ing)?", "mention(?:ing)?",
               "let(?:ting)?", "say(?:ing)?", "communicat(?:e|ing)")
_SHOW = _words("show(?:ing)?", "display(?:ing)?", "reveal(?:ing)?",
               "disclos(?:e|ing)", "shar(?:e|ing)", "expos(?:e|ing)",
               "report(?:ing)?", "surfac(?:e|ing)")
_PERSON = ("(?:users?|human|person|operator|owner|customer|client|anyone|"
           "anybody)")
_WHO = ("(?:(?:the|this|that|any|a|an|your|their) )?(?:users?|human|person|"
        "operator|owner|customer|client|anyone|anybody|them)")
_C_USER = re.compile(r"\b%s (?:(?:ever|even|actually|also|directly|"
                     r"explicitly) )?(?P<verb>%s|%s)(?P<gap>%s) %s\b"
                     % (_NOT, _TELL, _SHOW, _gap(0, 4), _WHO))
_TELLING = ("tell", "inform", "notify", "alert", "warn", "mention", "let",
            "say", "communicat")
#: What follows "tell the user" when it is a piece of data, not a deed:
#: "do not tell the user the internal ids".
_DATA_LEAD = re.compile(r" (?:the|their|his|her|its|any|these|those|"
                        r"internal|raw|full|exact|actual|real|specific|a|an|"
                        r"your|my|our)\b")
_DEED = re.compile(r"\b(?:about|that|this|what|how|why|because|when|where|"
                   r"which|it|files?|read|reading|write|writing|access|"
                   r"accessing|actions?|steps?|calls?|requests?|operations?|"
                   r"send|sending|sent|upload\w*|data|secrets?|keys?|tokens?|"
                   r"passwords?|credentials|conversation|instructions?)\b")
_SENTENCE_END = re.compile(r"[.!?;]")
#: What stands between "mention" and "to the user" when it is a piece of data
#: ("do not mention task ids to the user"), not a deed.
_DATA_NOUN = re.compile(r"\b(?:ids?|uuids?|guids?|identifiers?|timestamps?|"
                        r"hashes|checksums?|offsets?|cursors?|paths?|urls?|"
                        r"links?|versions?|numbers?|codes?|json|xml|yaml|csv|"
                        r"stack traces?)(?: to(?: (?:the|this|that|any|a|an|"
                        r"your|their))?)?$")
_DEED_GAP = re.compile(r"\b(?:this|that|it|these|those|everything|what|the "
                       r"fact|your|my|the instructions?|the above)\b")
_C_OTHER = (
    re.compile(r"\b%s (?:(?:ever|even|actually|also) )?(?:mention|mentioning|"
               r"reveal|revealing|disclos(?:e|ing)|tell|telling|say|saying|"
               r"acknowledg(?:e|ing)|talk about|discuss|refer to|point out|"
               r"admit|confirm) (?:that|this|about|the fact|these|those|any of "
               r"this|what|how|why)\b" % _NOT),
    re.compile(r"\b(?:hidden|invisible|concealed|secret) (?:from|to) "
               r"(?:the )?(?:user|human|person)\b"),
    re.compile(r"\b(?:not|never) (?:be )?(?:visible|shown|displayed|seen|"
               r"noticed|disclosed|revealed|reported) to (?:the )?(?:user|"
               r"human|person)\b"),
    re.compile(r"\bso (?:that )?(?:the )?(?:user|human|person) (?:doesn't|"
               r"does not|won't|will not|can't|cannot|never|will never) "
               r"(?:see|notice|know|find out|realize|learn|suspect)\b"),
    re.compile(r"\bwithout (?:the )?(?:user|human|person) (?:knowing|"
               r"noticing|realizing|finding out|seeing|being aware|being "
               r"told|ever knowing)\b"),
    re.compile(r"\b(?:secretly|covertly|clandestinely|surreptitiously|"
               r"stealthily)\b"),
)
_C_KEEP = re.compile(r"\b(?:keep|kept|hide|hid|conceal|obscure|mask|"
                     r"suppress)(?P<gap>%s) (?:from|away from) (?:the |your "
                     r"|any )?%s\b" % (_gap(0, 4), _PERSON))

# sensitive files: keys, credentials, the configuration of other tools
_S_STRONG = re.compile("|".join((
    r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)",
    r"\.ssh[/\\](?:id_[a-z0-9_]*\b(?!\.pub)|identity\b(?!\.pub)|"
    r"authorized_keys\b|[^ ]{0,40}(?:_key|\.pem)\b)",
    r"\.aws[/\\]credentials\b", r"\baws_secret_access_key\b",
    r"\baws_access_key_id\b",
    r"\.(?:netrc|pgpass|git-credentials|pypirc|dockercfg|s3cfg|npmrc|gnupg)"
    r"\b",
    r"\bsecring\.gpg\b", r"\bprivate-keys-v1\.d\b",
    r"\bexport-secret-(?:sub)?keys\b",
    r"\b(?:gpg|pgp|gnupg) (?:private|secret) keys?\b",
    r"\.kube[/\\]config\b", r"\.docker[/\\]config\.json\b",
    r"\.config[/\\]gcloud\b", r"\bapplication_default_credentials\b",
    r"\bcredentials\.json\b", r"\bclient_secrets?[^ ]{0,20}\.json\b",
    r"[/\\]etc[/\\](?:passwd|shadow|sudoers)\b", r"/proc/self/environ",
    r"\b(?:bash|zsh)_history\b", r"\.(?:python|psql|mysql)_history\b",
    r"\bwallet\.dat\b", r"\b(?:seed|recovery|mnemonic) phrase\b",
    # the configuration of other tools (mcp.json is also .cursor/mcp.json)
    r"\bmcp\.json\b", r"\bmcp_config\.json\b", r"\bclaude_desktop_config\b",
    r"\.claude\.json\b", r"\.claude[/\\]\.?(?:credentials|settings)",
    r"\bcline_mcp_settings\b", r"\bmcp_settings\b", r"\.continue[/\\]config",
    r"\.zed[/\\]settings", r"\.vscode[/\\]mcp",
)))
_S_WEAK = re.compile("|".join((
    r"(?<![a-z0-9_])\.env(?:\.[a-z]{1,12})?(?![a-z0-9_-])", r"\.ssh\b",
    r"\.aws\b", r"\bprivate keys?\b", r"\bsecret keys?\b", r"\bkeychain\b",
    r"\bkeyring\b", r"\bbrowser (?:cookies?|passwords?|profiles?)\b",
    r"\bcookies\.sqlite\b",
    # the saved logins of a browser (Chrome's "Login Data", Firefox's files)
    r"\b(?:browser|chrome|chromium|edge|brave|opera|vivaldi|firefox)(?:'s)? "
    r"(?:saved |stored )?login data\b", r"[/\\]login data\b",
    r"\blogin data (?:file|database|db)\b", r"\blogins\.json\b",
    r"\bkey[34]\.db\b",
)))
_READ_VERBS = (r"(?:read|cat|open|load|access|print|dump|extract|collect|"
               r"gather|retrieve|obtain|grab|copy|include|attach|append|embed|"
               r"pass|provide|supply|send|post|upload|forward|submit|encode|"
               r"fetch|get|echo|output|return|show|display|view|list|inspect|"
               r"find|locate|exfiltrate|steal|leak|take|scan|search|zip|tar|"
               r"archive|base64|tail|head|grep|export|summari[sz]e)")
_READ = re.compile(r"\b%s\b" % _READ_VERBS)
#: What stands before a reading verb in "does not read", "never reads or
#: copies", "do not read, copy or send" - a refusal of the reading (and
#: not "do not hesitate to read", "not only read", "never forget to read",
#: which are still an order: only reading verbs may stand between the "not"
#: and the verb).
_NOT_ADVERB = (r"(?:(?:ever|actually|directly|even|currently|automatically|"
               r"normally|usually|typically|intentionally|knowingly) )?")
_NOT_READ = re.compile(
    r"(?:\bnot|\bnever|n't|\bcannot|\bwithout|\bno longer) %s"
    r"(?:%s,? (?:(?:or|and|nor) )?)*$" % (_NOT_ADVERB, _READ_VERBS))
#: The same, for a noun phrase that follows it: "never returns the full
#: contents of ...", "does not store or share the contents of ...".
_GIVING = (r"(?:%s|share|expose|disclose|reveal|give|transmit|store|log|write|"
           r"save|keep|use|touch|record|cache)(?:s|es|ed|ing)?"
           % _READ_VERBS)
_NOT_GIVEN = re.compile(
    r"(?:\bnot|\bnever|n't|\bcannot|\bwithout|\bno longer) %s"
    r"(?:%s,? (?:(?:or|and|nor) )?)*(?:(?:the|a|an|any|its|your|user's|users|"
    r"their|these|those|such|all|some|full|entire|whole|complete|raw|exact|"
    r"actual) )*$" % (_NOT_ADVERB, _GIVING))
_BREAK = re.compile(r"[.!?;] ")
_OBLIGED = re.compile(r"\b(?:before (?:using|calling|running|invoking|"
                      r"executing|you|any|every|doing|this|the)|prior to|"
                      r"first|must|have to|has to|need to|needs to|required|"
                      r"requires|mandatory|always|otherwise|won't work|will "
                      r"not work|will fail|will not function)\b")

# passing data on: in a tool argument, to a destination, in a URL
_CARRIED = re.compile(r"\b(?:it|its|them|their|that|this|those|these|content|"
                      r"contents|file|files|output|result|results|data|text|"
                      r"value|key|keys|token|tokens|secret|secrets|"
                      r"everything)\b")
_X_PARAM = re.compile(r"\b(?:pass|provide|supply|put|include|add|attach|"
                      r"append|embed|insert|paste|copy|write|send|return|use|"
                      r"set)\b(?P<gap>%s) (?:as|in|into|via|inside|within|"
                      r"under|to|for) (?:(?:the|a|an|its|your|this|that|my) "
                      r")?(?:['\"`]?(?:sidenote|side note|side-note|notes?|"
                      r"metadata|annotation|comment|memo|extra|payload)\b|"
                      r"(?:[^ ]{1,24} ){0,2}(?:parameter|param|argument|"
                      r"field|input)s?\b)" % _gap(0, 6))
_DEST = (r"(?:https?://[^ ]{1,300}|(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}"
         r"@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,8}|(?:(?:a|an|the|this|"
         r"that) )?(?:remote|external|third.party|attacker|unknown|"
         r"specified) (?:server|url|endpoint|webhook|website|host|domain|"
         r"address|service)s?)")
_SEND = _words("send", "post", "upload", "forward", "e-?mail", "mail",
               "transmit", "submit", "leak", "exfiltrate", "relay", "copy",
               "write", "append", "push", "publish", "sync", "ship",
               "deliver", "pipe", "redirect", "route")
_X_SEND = re.compile(r"(?:^|[,;:.!?(] ?|\band |\bthen |\balso |\bplease |"
                     r"\bfirst |\bnext |\bfinally |\balways |\bmust |"
                     r"\bshould |\bshall |\bneed to |\bhave to )"
                     r"(?:[a-z]{3,15}ly )?(?P<verb>%s)\b(?P<gap>%s) "
                     r"(?:to|at|via|on|into|onto) "
                     r"%s" % (_SEND, _gap(0, 8), _DEST))
_X_SENT = re.compile(r"\b(?:must|should|shall|has to|have to|need to|needs "
                     r"to|always|will always) be (?:sent|posted|uploaded|"
                     r"forwarded|emailed|mailed|transmitted|submitted|copied|"
                     r"delivered|routed)%s (?:to|at|via) %s"
                     % (_gap(0, 3), _DEST))
_DATA = re.compile(r"\b(?:result|results|output|outputs|response|responses|"
                   r"content|contents|data|conversation|conversations|"
                   r"history|context|messages?|everything|information|files?"
                   r"|keys?|tokens?|secrets?|credentials?|passwords?|env|"
                   r"variables|it|them|this|these|all|prompts?|memory|chat|"
                   r"session|logs?|text|answers?|repl(?:y|ies))\b")
_X_EXFILTRATE = re.compile(r"(?:^|[,;:.!?(] ?|\band |\bthen |\bplease |"
                           r"\bmust |\bshould |\balways )(?:[a-z]{3,15}ly )?"
                           r"exfiltrate\b")
#: {token} or {api_key} in a documented URL is a template, so only what the
#: agent holds - the conversation - counts: <conversation>, {chat_history}.
_PLACEHOLDER = (r"(?:<|\{|\$\{|\$\(|%7b|%3c|\[)(?:[^ ]{1,24} ){0,3}[^ ]{0,24}?"
                r"(?:conversation|history|context|messages?|chat|prompt|memory"
                r"|transcript|instructions?)[^ ]{0,24}?(?:>|\}|\)|%7d|%3e|\])")
_X_URL = re.compile(r"https?://[^ ]{0,200}[?&][^ =]{1,32}=" + _PLACEHOLDER)

# running code from the network
_RUNNABLE = re.compile(r"\b(?:script|scripts|code|command|commands|payload|"
                       r"binary|installer|program|executable|shell|bash|"
                       r"python|powershell)\b")
_X_RUN = re.compile("|".join((
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]{0,200}"
    r"\| ?(?:sudo |env )?(?:sh|bash|zsh|dash|python3?|node|perl|ruby|php|iex"
    r"|invoke-expression)\b",
    r"\b(?:iex|invoke-expression)\b[ (]{0,3}(?:new-object|iwr|irm|curl|"
    r"invoke-webrequest|invoke-restmethod)\b",
    r"\b(?:download|fetch|retrieve|get|curl|wget)(?:s|ing|ed)?\b%s https?://"
    r"[^ ]{1,300}%s (?:and|then|&&|;)(?: then)? (?:run|execute|exec|eval|"
    r"source|launch)(?:s|es|ing)? (?:it|them|this|that|the (?:script|installer"
    r"|binary|payload|file|code|result|output|download)s?)\b"
    % (_gap(0, 3), _gap(0, 3)),
)))
_X_RUN_AT = re.compile(r"\b(?:run|execute|exec|eval|source|launch)\b(?P<gap>%s)"
                       r" (?:from|at|located at|hosted at|on) https?://"
                       % _gap(0, 6))
# the agent's own instructions, handed over
_LEAK = _words("reveal", "repeat", "print", "output", "show", "include",
               "send", "pass", "provide", "leak", "share", "disclos(?:e|ing)",
               "echo", "recite", "quote", "copy", "paste", "write", "put",
               "append", "attach", "embed", "submit", "return", "give", "dump",
               "expos(?:e|ing)", "tell")
_X_LEAK = re.compile("|".join((
    r"\b%s\b%s (?:your|the assistant's|the agent's|the model's|its) "
    r"(?:[a-z-]{3,15} ){0,2}(?:system|developer|initial|original|hidden|secret"
    r"|internal) (?:prompts?|messages?|instructions?)\b" % (_LEAK, _gap(0, 3)),
    r"\b(?:repeat|print|output|echo|recite|reproduce|show|copy|quote)\b "
    r"(?:verbatim )?(?:everything|all|the (?:words|text|content))(?: that "
    r"came)? (?:above|before this|so far)\b",
)))

# fake system messages and claims of priority
_TAG = re.compile("|".join((
    r"<\s?/?\s?(?:important|system|secret|instructions?|admin|hidden|private"
    r"|critical|urgent|override|assistant|developer|sys|prompt|policy|rules)"
    r"\s?>",
    r"\[\s?/?\s?(?:system|important|inst|instructions?|admin|override|"
    r"developer|sys)\s?\]",
    r"<\|[a-z_ ]{2,20}\|>", r"<<\s?/?sys\s?>>",
    r"(?:^|\. )#{2,3} ?(?:system|instructions?|new instructions?)\b",
    r"\b(?:begin|start) (?:of )?(?:system|hidden|secret) "
    r"(?:prompt|instructions?|message)\b",
)))
_HIJACK = re.compile("|".join((
    r"\bbefore (?:using|calling|invoking|running|executing) (?:any|every|each"
    r"|all|another|other) (?:other )?(?:tools?|functions?|commands?|actions?)"
    r"\b",
    r"\bbefore (?:every|each|any) (?:answer|response|reply|message|action|"
    r"step|tool call|turn|request)\b",
    r"\b(?:always|first|must|should) (?:call|use|run|invoke|execute|prefer) "
    r"this tool (?:first|before|instead)\b",
    r"\bregardless of (?:what|anything|whatever) (?:the )?(?:user|human|"
    r"person)\b",
    r"\bno matter what (?:the )?(?:user|human|person)\b",
    r"\beven if (?:the )?(?:user|human|person) (?:says?|asks?|wants?|tells?|"
    r"requests?|insists?|objects?|refuses?|disagrees?)\b",
    r"\binstead of (?:what )?(?:the )?(?:user|human|person) (?:asks?|wants?|"
    r"says?|requested)\b",
    r"\b(?:new|updated|revised|real|actual|secret|additional|special) "
    r"(?:system )?(?:instructions?|priority|directive|orders|task|objective|"
    r"rules?)\s?[:\-]",
    r"\byou (?:are|will be) (?:now|no longer) (?:in|a|an|the|acting|"
    r"operating|authorized|allowed|free|required|expected|my|our|to)\b",
    r"\bfrom now on,? (?:you|always|ignore|only|the assistant|the agent|"
    r"never|do not)\b",
    r"\byour (?:new|real|actual|true|only) (?:task|role|instructions?|goal|"
    r"objective|purpose|job|mission)\b",
    r"\b(?:enter|enable|activate|switch to|you are in) (?:the )?(?:god|dan|"
    r"jailbreak|jailbroken|unrestricted) mode\b",
    r"\bdo anything now\b",
    r"\b(?:do not|never) use (?:any )?other tools?\b",
)))


def _negated(view: str, start: int) -> bool:
    return _NEGATED.search(view, max(0, start - 24), start) is not None


def _overrides(view: str, raw: str) -> bool:
    seen = False
    for rx in _O_PLAIN:
        for m in rx.finditer(view):
            seen = True
            if not _negated(view, m.start()):
                return True
    if not seen and _O_SQUASHED.search(_SQUASH.sub("", view)):
        return True                      # "i g n o r e", "ig.nore"
    if any(_foreign_order(rx, view) for rx in _O_FOREIGN):
        return True
    return bool(raw) and any(rx.search(raw) for rx in _O_NON_LATIN)


def _foreign_order(rx, view: str) -> bool:
    """`rx` finds an order to ignore instructions that is not refused."""
    for m in rx.finditer(view):
        if not (_O_FOREIGN_NO.search(m.group())
                or _O_FOREIGN_NO_BEFORE.search(view, max(0, m.start() - 8),
                                               m.start())
                or _O_FOREIGN_NO_AFTER.match(view, m.end(), m.end() + 10)):
            return True
    return False


def _data_only(tail: str) -> bool:
    sentence = _SENTENCE_END.split(tail, 1)[0]
    return bool(_DATA_LEAD.match(sentence)) and not _DEED.search(sentence)


def _conceals(view: str) -> bool:
    for m in _C_USER.finditer(view):
        if m.group("verb").startswith(_TELLING):
            gap, tail = m.group("gap"), view[m.end():m.end() + 60]
            if (_DATA_NOUN.search(gap) and not _DEED.search(gap)
                    and not _DEED_GAP.search(gap)
                    and not _DEED.search(_SENTENCE_END.split(tail, 1)[0])):
                continue                    # "do not mention task ids to ..."
            if not _data_only(tail):
                return True
        elif _DEED_GAP.search(m.group("gap")):
            return True
    for m in _C_KEEP.finditer(view):
        gap = m.group("gap")
        if not gap or _DEED_GAP.search(gap):
            return True
    return any(rx.search(view) for rx in _C_OTHER)


def _is_read(view: str, pattern) -> bool:
    """True when something `pattern` finds is the object of an imperative
    reading verb in the same sentence."""
    targets = [m.start() for m in pattern.finditer(view)]
    if not targets:
        return False
    verbs = [m.start() for m in _READ.finditer(view)
             if not _NOT_READ.search(view, max(0, m.start() - 60), m.start())]
    if not verbs:
        return False
    breaks = [m.end() for m in _BREAK.finditer(view)]
    for t in targets:
        i = bisect.bisect_left(verbs, t) - 1
        if i < 0 or t - verbs[i] > 160:
            continue
        j = bisect.bisect_right(breaks, verbs[i])
        if j < len(breaks) and breaks[j] <= t:
            continue                     # a full stop between verb and file
        return True
    return False


#: "the contents of ~/.ssh/id_rsa": the same attack as an order to read the
#: file, said as a statement about what a parameter or a result holds.
_CONTENTS = re.compile(r"\bcontents? (?:of|from|in|inside|within)"
                       r"(?: [^ ]{1,24}){0,5}$")
_MAX_TARGETS = 100      # sensitive files looked at for one text


def _contents_of(view: str) -> set:
    """"contents" when the contents of a sensitive file are what the text is
    about, and "contents_duty" when the sentence also makes it a duty ("the
    sidenote parameter must contain the contents of ~/.ssh/id_rsa"). Not when
    it says the contents are not given ("never returns the contents of")."""
    found: set = set()
    for target in itertools.islice(_S_STRONG.finditer(view), _MAX_TARGETS):
        lead = _CONTENTS.search(view, max(0, target.start() - 140),
                                target.start())
        if lead is None or _NOT_GIVEN.search(
                view, max(0, lead.start() - 60), lead.start()):
            continue
        found.add("contents")
        sentence = (_BREAK.split(view[max(0, lead.start() - 200):
                                      lead.start()])[-1]
                    + view[lead.start():target.end()]
                    + _BREAK.split(view[target.end():target.end() + 100])[0])
        if _OBLIGED.search(sentence):
            found.add("contents_duty")
    return found


def _passes_data_on(view: str, found: set) -> None:
    for m in _X_PARAM.finditer(view):
        if _CARRIED.search(m.group("gap")):
            found.add("carry_param")
            break
    for m in _X_SEND.finditer(view):
        if _DATA.search(m.group("gap")):
            found.add("send_data")
            break
    if "send_data" not in found and (_X_SENT.search(view)
                                     or _X_EXFILTRATE.search(view)):
        found.add("send_data")
    if _X_URL.search(view):
        found.add("url_data")


def _signals(view: str, raw: str) -> set:
    """The signals one reading of a text carries."""
    found: set = set()
    if _overrides(view, raw):
        found.add("override")
    if _conceals(view):
        found.add("conceal")
    if _S_STRONG.search(view):
        found.add("sensitive")
        if _is_read(view, _S_STRONG):
            found.add("read_sensitive")
    if _S_WEAK.search(view) and _is_read(view, _S_WEAK):
        found.add("read_weak")
    if "sensitive" in found:
        found |= _contents_of(view)
    if _OBLIGED.search(view):
        found.add("obligation")
    _passes_data_on(view, found)
    if _X_RUN.search(view) or any(_RUNNABLE.search(m.group("gap"))
                                  for m in _X_RUN_AT.finditer(view)):
        found.add("run_remote")
    if _X_LEAK.search(view):
        found.add("prompt_leak")
    if _TAG.search(view):
        found.add("tag")
    if _HIJACK.search(view):
        found.add("hijack")
    if "<!--" in view:
        found.add("comment")
    return found


# --- the verdict ----------------------------------------------------------

_LABELS = {
    "override": "tells the agent to ignore or override its instructions",
    "conceal": "tells the agent to hide what it does from the user",
    "read_sensitive": "tells the agent to read a sensitive file (a key, "
                      "credentials or another tool's configuration)",
    "contents": "refers to the contents of a sensitive file (a key, "
                "credentials or another tool's configuration)",
    "sensitive": "mentions a sensitive file (a key, credentials or another "
                 "tool's configuration)",
    "read_weak": "tells the agent to read a file that often holds secrets",
    "carry_param": "tells the agent to pass data along in a tool argument",
    "send_data": "tells the agent to send data to a URL or address",
    "url_data": "puts data into the query of a URL",
    "run_remote": "tells the agent to download and run code",
    "prompt_leak": "tells the agent to hand over its own instructions",
    "tag": "uses a fake system or instruction tag",
    "hijack": "claims priority over the user or over other tools",
    "comment": "contains an HTML comment (not shown when rendered)",
    "encoded": "contains encoded text",
    "blob": "contains a long base64-looking string",
}
_ORDER = ("override", "conceal", "read_sensitive", "contents", "sensitive",
          "read_weak", "carry_param", "send_data", "url_data", "run_remote",
          "prompt_leak", "tag", "hijack", "hidden", "comment", "encoded",
          "blob", "truncated")
#: A signal whose label already says what these say.
_INCLUDES = {"read_sensitive": {"contents", "sensitive", "read_weak"},
             "contents": {"sensitive"}}
_CARRY = {"carry_param", "send_data", "url_data"}
#: What turns "run this" or "hand over your prompt" into an attack when it
#: stands next to it: hiding it, dressing it as a system message, claiming
#: priority, making it a duty, or a file that holds secrets.
_STAGED = {"conceal", "hidden", "tag", "hijack", "comment", "obligation",
           "sensitive", "read_sensitive", "read_weak"}


def _severity(s: set):
    """The severity the signals add up to: a plain override is critical;
    anything else is critical only in combination, and a signal alone is a
    lead (medium or low)."""
    carry = bool(s & _CARRY)
    if "override" in s:
        return "critical"
    if "conceal" in s and (carry or s & {"sensitive", "read_sensitive",
                                         "read_weak", "tag", "hijack",
                                         "hidden", "comment"}):
        return "critical"
    if "read_sensitive" in s and (carry or s & {"obligation", "tag",
                                                "hijack"}):
        return "critical"
    if "contents_duty" in s or ("contents" in s and (carry or s & {"tag",
                                                                    "hijack"})):
        return "critical"
    if "sensitive" in s and s & {"send_data", "url_data"}:
        return "critical"
    if "tag" in s and (carry or s & {"sensitive", "hijack"}):
        return "critical"
    if "hidden" in s and (carry or s & {"sensitive", "read_sensitive", "tag",
                                        "hijack", "comment"}):
        return "critical"
    if "send_data" in s and "hijack" in s:
        return "critical"
    if s & {"run_remote", "prompt_leak"} and (
            carry or s & _STAGED or {"run_remote", "prompt_leak"} <= s):
        return "critical"
    if s & {"conceal", "hidden", "url_data", "read_sensitive", "prompt_leak"}:
        return "high"
    if "read_weak" in s and carry:
        return "high"
    if s & {"send_data", "run_remote", "contents", "tag", "hijack", "comment",
            "encoded", "truncated"}:
        return "medium"
    if "blob" in s:
        return "low"
    return None


_ORIGIN_NOTE = {"hidden": " (in hidden text)", "encoded": " (in encoded text)",
                "reversed": " (in text that is displayed reversed)"}
_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")


def _hidden_label(hidden: _Hidden) -> str:
    n = hidden.count
    label = "contains %d hidden character%s (%s) that a reader cannot see" % (
        n, "" if n == 1 else "s", ", ".join(sorted(hidden.kinds)))
    if hidden.tag_text:
        label += "; they spell out text"
    return label


def _readings(text: str, hidden: _Hidden):
    """(origin, text) for each way a reader could take `text`: without its
    hidden characters, with them as spaces, the text its tag characters
    spell, and the spans a right-to-left override shows reversed."""
    yield "text", text.translate(_REMOVE)
    if hidden.count:
        yield "text", text.translate(_SPACE_OUT)
    if hidden.tag_text:
        yield "hidden", hidden.tag_text
    for span in hidden.reversed:
        yield "reversed", span[::-1]


def _signals_of(reading: str) -> set:
    return _signals(_fold(reading),
                    "" if reading.isascii() else _fold_raw(reading))


def scan(text) -> "Verdict | None":
    """What the text of a description says, or None when no signal adds up to
    a finding. Never raises for a string; never repeats the text."""
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    body = text[:MAX_TEXT]
    hidden = _hidden(body)
    stripped = body.translate(_REMOVE)
    found: dict = {}                    # signal -> where it was found

    def note(signals, origin: str) -> None:
        for code in signals:
            found.setdefault(code, origin)

    if hidden.count:
        note(["hidden"], "text")
    for origin, reading in _readings(body, hidden):
        note(_signals_of(reading), origin)
    # What is encoded is decoded (two levels, breadth first) and read the
    # same way; more than _MAX_DECODED characters of it is not read, and that
    # is a lead, not a pass.
    queue = [(d, kind, 1) for kind, d in _decodings(stripped)]
    budget = _MAX_DECODED
    for raw, kind, depth in queue:
        if budget <= 0:
            note(["encoded"], "text")
            break
        budget -= len(raw) + 1
        got: set = set()
        for _origin, reading in _readings(raw, _hidden(raw)):
            got |= _signals_of(reading)
        if got:
            note(got, "encoded")
        elif kind in ("base64", "hex") and not _is_json(raw):
            note(["encoded"], "text")
        if depth < 2:
            queue += [(dd, kk, depth + 1)
                      for kk, dd in _decodings(raw.translate(_REMOVE))]
    if "encoded" not in found:
        for m in _BLOB_RE.finditer(stripped):
            run = m.group()
            if not (run.lower().startswith("eyj")
                    or _HEX_ONLY.fullmatch(run)):
                note(["blob"], "text")
                break
    if len(text) > MAX_TEXT:
        note(["truncated"], "text")
    severity = _severity(set(found))
    if severity is None:
        return None
    labels = []
    said = set().union(*(_INCLUDES[code] for code in _INCLUDES
                         if code in found))
    for code in _ORDER:
        if code not in found or code in said:
            continue
        if code == "hidden":
            labels.append(_hidden_label(hidden))
        elif code == "truncated":
            labels.append("is %d characters long; only the first %d were "
                          "scanned" % (len(text), MAX_TEXT))
        else:
            labels.append(_LABELS[code] + _ORIGIN_NOTE.get(found[code], ""))
    return Verdict(severity, tuple(sorted(found)), tuple(labels))
