"""Load the technology-to-view mapping and answer questions about it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_VIEWS_FILE = Path(__file__).with_name("views.yml")

# The one distinction that matters about a traffic source: a capture records
# requests that happened, a collection records requests somebody meant to make.
# Absence from a capture is weak evidence of disuse; absence from a collection
# is no evidence at all. `views.yml` spells these as `kind: observed` and
# `kind: curated`, and only the curated case changes any behaviour.
CURATED = "curated"


@dataclass(frozen=True)
class TechView:
    tech: str
    view: str
    kind: str | None = None

    @property
    def observed(self) -> bool:
        """Did something actually watch this, or did someone write it down?

        Only collections carry the distinction: a HAR file and a Burp export
        record requests that happened, a Postman collection records requests
        somebody meant to make. Everything else -- code, specifications,
        gateway config -- is a real artifact, so it counts as observed.
        """
        return self.kind != CURATED


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

    def techs_by_view(self, catalog: dict) -> dict[str, list[str]]:
        """Bucket every technology this noir build knows into its view.

        The catalog is the authority for which technologies exist; this file is
        the authority for what each one speaks for. Together they produce the
        `--only-techs` list that isolates one view per scan.
        """
        buckets: dict[str, list[str]] = {}
        for tech in catalog:
            buckets.setdefault(self.lookup(tech).view, []).append(tech)
        return {view: sorted(techs) for view, techs in buckets.items()}

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
