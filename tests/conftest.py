import pytest

from alibi.collect import RawEndpoint
from alibi.views import ViewMap


@pytest.fixture
def view_map():
    return ViewMap.load()


@pytest.fixture
def endpoint():
    """Build a noir endpoint without going near a subprocess."""

    def make(url, method="GET", technology="python_flask", *, tags=(),
             internal=False, source="test", code_paths=(), source_root=""):
        return RawEndpoint(
            url=url,
            method=method,
            technology=technology,
            source=source,
            tags=tuple(tags),
            code_paths=tuple(code_paths),
            internal=internal,
            source_root=source_root,
        )

    return make
