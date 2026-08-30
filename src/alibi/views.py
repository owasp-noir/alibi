"""Load the technology-to-view mapping and answer questions about it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_VIEWS_FILE = Path(__file__).with_name("views.yml")

# Absence of an endpoint from a curated collection says nothing -- somebody
# simply never wrote that request down. Absence from an observed capture is
# weak evidence of disuse. Rules that reason about absence consult this.
OBSERVED = "observed"
CURATED = "curated"


@dataclass(frozen=True)
class TechView:
    tech: str
    view: str
    kind: str | None = None

    @property
    def observed(self) -> bool:
        return self.kind == OBSERVED


class ViewMap:
    def __init__(self, data: dict) -> None:
        self._default: str = data.get("default", "code")
        self._views: dict[str, dict] = data.get("views", {})
        self._techs: dict[str, TechView] = {}
        for tech, spec in (data.get("techs") or {}).items():
            if isinstance(spec, dict):
                self._techs[tech] = TechView(tech, spec["view"], spec.get("kind"))
            else:
                self._techs[tech] = TechView(tech, spec)

    @classmethod
    def load(cls, path: Path | None = None) -> "ViewMap":
        source = path or _VIEWS_FILE
        with source.open(encoding="utf-8") as handle:
            return cls(yaml.safe_load(handle))

    @property
    def views(self) -> list[str]:
        return list(self._views)

    @property
    def mapped_techs(self) -> set[str]:
        return set(self._techs)

    def is_predicate(self, view: str) -> bool:
        """Gateways and infra declare routing rules, not endpoints.

        A single `location /api/` covers every path beneath it, so these views
        answer "does this cover X?" rather than "does this contain X?" and can
        never be compared as plain sets.
        """
        return self._views.get(view, {}).get("kind") == "predicate"

    def describe(self, view: str) -> str:
        return self._views.get(view, {}).get("description", "")

    def lookup(self, tech: str) -> TechView:
        """Place a technology. Anything unlisted is code.

        Noir reports a `language` for every one of its 200-plus language
        analyzers and they all describe running code, so listing them here
        would be busywork that goes stale. The cost of the default is that a
        *new specification analyzer* would silently be read as code -- which is
        what `alibi doctor` exists to catch.
        """
        found = self._techs.get(tech)
        if found is not None:
            return found
        return TechView(tech, self._default)
