import pytest

from alibi.normalize import Key, normalize


@pytest.mark.parametrize(
    "url,expected",
    [
        # The five spellings of one parameter slot, as noir actually emits them.
        ("/api/users/<int:user_id>", "/api/users/{}"),
        ("/users/{id}", "/users/{}"),
        ("/api/catalog/{id}", "/api/catalog/{}"),
        ("/v1/pets/{petId}", "/v1/pets/{}"),
        ("/posts/:id", "/posts/{}"),
        # Optional and typed forms name the same slot.
        ("/reports/{id:int}", "/reports/{}"),
        ("/reports/{id?}", "/reports/{}"),
        ("/reports/:id?", "/reports/{}"),
        # Named capture groups out of gateway configs.
        (r"/user/(?<uid>\d+)/edit", "/user/{}/edit"),
        (r"/user/(?P<uid>[0-9]+)/edit", "/user/{}/edit"),
        # More than one parameter in a single segment.
        ("/tiles/{z}-{x}-{y}", "/tiles/{}-{}-{}"),
    ],
)
def test_parameter_notations_reduce_to_one_token(url, expected):
    assert normalize(url).key.path == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        # Anything that keeps matching past a slash is a different token.
        ("/files/<path:subpath>", "/files/*"),
        ("/static/**", "/static/*"),
        ("/admin/.*", "/admin/*"),
        ("/blog/{*slug}", "/blog/*"),
        ("/assets/*", "/assets/*"),
    ],
)
def test_spanning_wildcards_are_distinct_from_single_segment_params(url, expected):
    result = normalize(url)
    assert result.key.path == expected
    assert result.spans_segments is True


def test_parameter_names_are_evidence_not_identity():
    """The whole premise: a slot's name must not affect what it matches."""
    flask = normalize("/users/<int:user_id>", "GET")
    spec = normalize("/users/{userId}", "GET")
    rails = normalize("/users/:id", "GET")

    assert flask.key == spec.key == rails.key
    assert flask.param_names == ("user_id",)
    assert spec.param_names == ("userId",)


def test_filenames_survive_the_regex_heuristic():
    """A dot is a regex metacharacter and also just a dot."""
    assert normalize("/assets/index.html").key.path == "/assets/index.html"
    assert normalize("/static/app.min.js").key.path == "/static/app.min.js"
    assert normalize("/admin/.*").key.path == "/admin/*"


def test_trailing_slash_does_not_split_one_endpoint_in_two():
    assert normalize("/api/v1/").key == normalize("/api/v1").key
    assert normalize("/").key.path == "/"


def test_repeated_slashes_collapse():
    assert normalize("//api//v1//x").key.path == "/api/v1/x"


def test_absolute_urls_keep_the_host_out_of_the_key():
    """A spec with a `servers` block must still match a relative code route."""
    absolute = normalize("https://api.example.com/v1/users", "POST")
    relative = normalize("/v1/users", "POST")

    assert absolute.key == relative.key
    assert absolute.host == "api.example.com"
    assert relative.host is None


def test_query_string_is_split_off_but_an_optional_param_is_not():
    with_query = normalize("/search?q=1")
    assert with_query.key.path == "/search"
    assert with_query.query == "q=1"

    optional = normalize("/posts/:id?")
    assert optional.key.path == "/posts/{}"
    assert optional.query is None


def test_methods_are_upper_cased_and_non_http_verbs_flagged():
    assert normalize("/x", "get").key.method == "GET"
    assert normalize("/x", "SEND").non_http is True
    assert normalize("/x", "POST").non_http is False


def test_renamed_reports_whether_rewriting_was_needed():
    assert normalize("/users/{id}").renamed is True
    assert normalize("/users/list").renamed is False


def test_empty_url_does_not_explode():
    assert normalize("", "GET").key == Key("GET", "/")


def test_a_dangling_question_mark_never_splits_an_endpoint():
    """`/search` and a captured `/search?` are the same endpoint."""
    assert normalize("/search?").key == normalize("/search").key
    # But a `?` in the middle is part of the path, not punctuation.
    assert normalize("/a?b").key.path == "/a?b"
