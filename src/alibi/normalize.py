"""Turn a noir endpoint URL into a key that survives crossing view boundaries.

Noir preserves each framework's own route syntax rather than inventing a
common one, which is the right call for a discovery tool -- the output stays
faithful to the source. It does mean the same endpoint arrives here spelled
five different ways::

    python_flask   /api/users/<int:user_id>
    aiohttp        /users/{id}
    java_spring    /api/catalog/{id}
    oas3           /v1/pets/{petId}
    rails          /posts/:id
    nginx          /admin/.*

The one rule that makes these comparable: **a path parameter's name is not
part of its identity.** ``{petId}`` in a spec and ``<int:user_id>`` in Flask
describe the same slot; only its position and how much of the path it swallows
matter. Names are kept as evidence so a report can show why two rows matched,
but they never reach the key.

Two placeholder tokens come out of this module:

``{}``
    Matches within a single path segment.
``*``
    Matches across segments. Flask's ``path`` converter, Spring's ``**``, and
    a bare ``.*`` in an nginx location all land here, because all three keep
    matching past a ``/``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# Sentinels stand in for substituted spans while the remaining literal text is
# inspected for raw regex. They use control characters so nothing in a real URL
# can collide with them.
_PARAM = "\x00P\x00"
_WILD = "\x00W\x00"

# <int:user_id>, <user_id>, <path:subpath>  -- Flask / Werkzeug, Bottle
_ANGLE = re.compile(r"<(?:(?P<conv>[A-Za-z_][\w.]*)\s*:)?(?P<name>[^<>/]*)>")

# {id}, {id:int}, {id?}, {*rest}, {**rest}  -- OpenAPI, Spring, ASP.NET, Laravel
_BRACE = re.compile(r"\{(?P<body>[^{}/]*)\}")

# (?<id>\d+), (?P<id>[0-9]+)  -- named capture groups from gateway configs
_NAMED_GROUP = re.compile(r"\(\?P?<(?P<name>[A-Za-z_]\w*)>[^)]*\)")

# :id, :id?  -- Rails, Express, Gin, Echo, Koa
_COLON = re.compile(r":(?P<name>[A-Za-z_]\w*)\??")

# *action, *, **  -- splat / catch-all
_SPLAT = re.compile(r"\*{1,2}(?P<name>[A-Za-z_]\w*)?")

# Converters that keep matching past a slash, so they behave like a splat.
_SPANNING_CONVERTERS = {"path", "any", "re"}

# What makes a leftover literal segment look like a hand-written regex rather
# than a real path component.
_REGEX_META = re.compile(r"[.\[\]()+\\^$|]")

# Segments that are purely "match anything from here on".
_BARE_WILDCARDS = {".*", ".+", ".*$", ".+$", "(.*)", "(.+)"}

# Noir reports a protocol per endpoint, and it is the right discriminator for
# what shares a URL space with what. `cli://gitops-engine/agent` is a command
# line, not a path: read as HTTP it becomes `/agent`, collides with any web
# route of that name, and gets asked whether a gateway routes to it.
#
# http and https describe one space -- a specification with an `https` server
# block documents the same endpoints the code serves -- so they collapse.
# Everything else keeps its own space and never matches across.
HTTP_PROTOCOLS = frozenset({"http", "https", ""})
HTTP = "http"

# Verbs outside HTTP's request/response model. Redundant with the protocol for
# well-formed input, kept because an analyzer that reports one without setting
# the other should still not have its STOMP frames compared to a REST contract.
NON_HTTP_METHODS = frozenset({"SEND", "SUBSCRIBE", "MESSAGE", "PUBLISH", "RECEIVE", "CLI"})

# A gateway route that answers on any verb.
WILDCARD_METHOD = "ANY"


@dataclass(frozen=True)
class Key:
    """What two endpoints must share to be considered the same endpoint."""

    method: str
    path: str
    protocol: str = HTTP

    @property
    def http(self) -> bool:
        return self.protocol == HTTP

    def __str__(self) -> str:
        if self.http:
            return f"{self.method} {self.path}"
        return f"{self.protocol}: {self.method} {self.path}"


@dataclass
class Normalized:
    """One noir endpoint, reduced to a key and the evidence behind it."""

    key: Key
    original_url: str
    original_path: str
    host: str | None = None
    query: str | None = None
    param_names: tuple[str, ...] = ()
    spans_segments: bool = False
    non_http: bool = False

    @property
    def renamed(self) -> bool:
        """True when normalization had to rewrite the path to reach the key.

        Drives the match grade: two endpoints whose originals already agreed
        matched exactly, while two that only agree after rewriting matched on
        template shape alone.
        """
        return self.original_path != self.key.path


def split_method(method: str) -> tuple[str, bool]:
    """Return the normalized method and whether it sits outside HTTP."""
    m = (method or "").strip().upper()
    if not m:
        return "GET", False
    return m, m in NON_HTTP_METHODS


def _canon_segment(seg: str, names: list[str]) -> tuple[str, bool]:
    """Reduce one path segment to placeholders. Returns (text, spans_segments)."""
    spans = False

    def take_angle(m: re.Match[str]) -> str:
        nonlocal spans
        conv = (m.group("conv") or "").lower()
        name = m.group("name")
        if name:
            names.append(name)
        if conv in _SPANNING_CONVERTERS:
            spans = True
            return _WILD
        return _PARAM

    def take_brace(m: re.Match[str]) -> str:
        nonlocal spans
        body = m.group("body")
        if body.startswith("*"):
            name = body.lstrip("*")
            if name:
                names.append(name)
            spans = True
            return _WILD
        # {id:int} and {id?} both name the slot `id`.
        name = body.split(":", 1)[0].rstrip("?")
        if name:
            names.append(name)
        return _PARAM

    def take_named_group(m: re.Match[str]) -> str:
        names.append(m.group("name"))
        return _PARAM

    def take_colon(m: re.Match[str]) -> str:
        names.append(m.group("name"))
        return _PARAM

    def take_splat(m: re.Match[str]) -> str:
        nonlocal spans
        name = m.group("name")
        if name:
            names.append(name)
        spans = True
        return _WILD

    # Angle and brace forms are handled first: both can contain a `:` that the
    # colon rule would otherwise tear apart (`<int:id>`, `{id:int}`).
    text = _ANGLE.sub(take_angle, seg)
    text = _BRACE.sub(take_brace, text)
    text = _NAMED_GROUP.sub(take_named_group, text)
    text = _COLON.sub(take_colon, text)
    text = _SPLAT.sub(take_splat, text)

    # A trailing `?` is punctuation either way -- an optional-parameter marker
    # (`{id}?`) or the empty query string on a captured URL (`/search?`) -- and
    # neither reading changes which handler runs.
    if text.endswith("?"):
        text = text[:-1]

    # Whatever is still literal may be raw regex from a gateway config.
    literal = text.replace(_PARAM, "").replace(_WILD, "")
    if literal:
        if literal in _BARE_WILDCARDS or seg in _BARE_WILDCARDS:
            spans = True
            return _WILD, spans
        if _REGEX_META.search(literal) and not _looks_like_filename(literal):
            return _PARAM, spans

    return text, spans


def _looks_like_filename(literal: str) -> bool:
    """Distinguish `index.html` from `.*`.

    A dot is the one regex metacharacter that shows up constantly in ordinary
    paths, so a segment whose only metacharacter is a dot between two normal
    runs is treated as a literal filename rather than a pattern.
    """
    if _REGEX_META.sub("", literal) == literal.replace(".", ""):
        return bool(re.fullmatch(r"[\w%-]+(\.[\w%-]+)+", literal))
    return False


def _split_query(url: str) -> tuple[str, str | None]:
    """Peel a query string off a relative path.

    A `?` in a route is ambiguous: it opens a query string, but it also marks
    an optional parameter in Express, Laravel and ASP.NET (`:id?`, `{id?}`).
    Only a `?` followed by something shaped like `key=value` is a query.

    A bare trailing `?` is left on the path deliberately. It is far more often
    an optional-parameter marker than an empty query string, and the parameter
    rules below know how to absorb it -- whereas stripping it here would hide
    the marker from them and leave a stray `?` in the key.
    """
    head, sep, tail = url.partition("?")
    if sep and "=" in tail:
        return head, tail
    return url, None


def normalize(url: str, method: str = "GET", protocol: str = HTTP) -> Normalized:
    """Reduce a noir endpoint URL, method and protocol to a comparable key."""
    raw = (url or "").strip()
    host: str | None = None

    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.netloc or None
        path = parts.path or "/"
        query = parts.query or None
    else:
        path, query = _split_query(raw)

    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path

    # `//api//v1` and `/api/v1` address the same resource.
    path = re.sub(r"/{2,}", "/", path)

    original_path = path
    names: list[str] = []
    spans = False
    out: list[str] = []

    for seg in path.split("/")[1:]:
        if seg == "":
            out.append("")
            continue
        canon, seg_spans = _canon_segment(seg, names)
        spans = spans or seg_spans
        out.append(canon)

    canon_path = "/" + "/".join(out)
    canon_path = canon_path.replace(_PARAM, "{}").replace(_WILD, "*")

    # A trailing slash never changes which handler runs, so it cannot be
    # allowed to split one endpoint into two keys. Gateways are the exception --
    # there a trailing slash marks a prefix -- and that is handled by the
    # coverage evaluator, which reads `original_path`, not the key.
    if len(canon_path) > 1 and canon_path.endswith("/"):
        canon_path = canon_path.rstrip("/")

    norm_method, odd_verb = split_method(method)
    space = HTTP if (protocol or "").lower() in HTTP_PROTOCOLS else protocol.lower()
    non_http = space != HTTP or odd_verb

    return Normalized(
        key=Key(method=norm_method, path=canon_path, protocol=space),
        original_url=raw,
        original_path=original_path,
        host=host,
        query=query,
        param_names=tuple(names),
        spans_segments=spans,
        non_http=non_http,
    )
