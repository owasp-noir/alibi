from alibi.views import ViewMap


def test_every_non_language_tech_is_placed_by_hand():
    """The default is only safe for language analyzers.

    Noir reports a `language` for analyzers that read code. Everything else is
    a document, a capture or routing config, and each one has to be assigned a
    view explicitly -- otherwise it silently reads as code and its whole view
    disappears from the comparison.
    """
    view_map = ViewMap.load()
    assert len(view_map.mapped_techs) == 49


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
    assert view_map.lookup("http_file").observed is False
    assert view_map.lookup("graphql_operation").observed is False
    assert view_map.lookup("postman").view == "traffic"
    assert view_map.lookup("graphql_operation").view == "traffic"
    assert view_map.lookup("graphql_sdl").view == "doc"


def test_schema_driven_platforms_count_as_implementation():
    """A Hasura or Strapi endpoint really answers requests."""
    view_map = ViewMap.load()
    for tech in ("hasura", "strapi", "supabase", "directus", "appwrite"):
        assert view_map.lookup(tech).view == "code"


def test_an_alternative_view_map_can_be_named_by_path_string(tmp_path):
    """`--views PATH` reaches `load` as a string, and a string has no `open`.

    Every scan with an alternative map died on that before noir ran -- the
    one flag for changing which view a technology speaks for could never be
    used.
    """
    alternative = tmp_path / "views.yml"
    alternative.write_text(
        "default: code\nviews:\n  code: {}\n  doc: {}\ntechs:\n  grpc: code\n",
        encoding="utf-8")

    view_map = ViewMap.load(str(alternative))
    assert view_map.lookup("grpc").view == "code"


def test_a_proto_with_http_annotations_is_implementation_not_contract():
    """`grpc: code`, and why.

    Noir's grpc analyzer emits an HTTP route from one thing only: an
    `option (google.api.http)` annotation. That annotation is what a
    gRPC-gateway generates its serving routes from, so the proto is where
    the HTTP surface is implemented, and the OpenAPI document next to it is
    generated from the proto. Filed as doc, the two corroborated each other
    and the Go code never entered the comparison -- flipt reported 0 of 42
    documented paths corroborated, Argo CD 0 of 106, and both were held back
    as views that never met. Filed as code, flipt corroborates 36 of 36.
    """
    assert ViewMap.load().lookup("grpc").view == "code"
