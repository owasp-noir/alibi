from alibi.views import ViewMap


def test_every_non_language_tech_is_placed_by_hand():
    """The default is only safe for language analyzers.

    Noir reports a `language` for analyzers that read code. Everything else is
    a document, a capture or routing config, and each one has to be assigned a
    view explicitly -- otherwise it silently reads as code and its whole view
    disappears from the comparison.
    """
    view_map = ViewMap.load()
    assert len(view_map.mapped_techs) == 48


def test_language_analyzers_fall_through_to_code():
    view_map = ViewMap.load()
    assert view_map.lookup("python_flask").view == "code"
    assert view_map.lookup("java_spring").view == "code"
    # Including one that does not exist yet.
    assert view_map.lookup("some_future_framework").view == "code"


def test_the_five_views_and_which_of_them_are_predicates():
    view_map = ViewMap.load()
    assert set(view_map.views) == {"code", "doc", "traffic", "gateway", "infra"}
    assert view_map.is_predicate("gateway") is True
    assert view_map.is_predicate("infra") is True
    assert view_map.is_predicate("code") is False
    assert view_map.is_predicate("doc") is False


def test_captures_and_collections_are_told_apart():
    """Absence from a capture is weak evidence; absence from a collection is none."""
    view_map = ViewMap.load()
    assert view_map.lookup("har").observed is True
    assert view_map.lookup("mitmproxy").observed is True
    assert view_map.lookup("postman").observed is False
    assert view_map.lookup("insomnia").observed is False
    assert view_map.lookup("postman").view == "traffic"


def test_schema_driven_platforms_count_as_implementation():
    """A Hasura or Strapi endpoint really answers requests."""
    view_map = ViewMap.load()
    for tech in ("hasura", "strapi", "supabase", "directus", "appwrite"):
        assert view_map.lookup(tech).view == "code"
