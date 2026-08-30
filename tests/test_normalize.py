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


def test_methods_are_upper_cased_and_non_http_verbs_flagged():  # noqa
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


def test_a_cli_command_is_not_an_http_path():
    """`cli://gitops-engine/agent` read as HTTP becomes `/agent`.

    Noir reports genuine non-web attack surface -- CLI arguments, Kafka topics,
    mobile deep links -- in the same endpoint list. Flattened into the HTTP
    space they collide with real routes and get asked whether a gateway routes
    to them, which is meaningless.
    """
    cli = normalize("cli://gitops-engine/agent", "CLI", "cli")
    http = normalize("/agent", "GET", "http")

    assert cli.key != http.key
    assert cli.key.protocol == "cli"
    assert cli.key.http is False
    assert http.key.http is True


def test_https_and_http_describe_one_space():
    """A spec with an `https` server block documents the code's own routes."""
    secure = normalize("https://api.example.com/v1/users", "GET", "https")
    plain = normalize("/v1/users", "GET", "http")
    assert secure.key == plain.key


def test_each_non_web_protocol_keeps_its_own_space():
    paths = [
        normalize("/topic", "PUBLISH", "kafka").key,
        normalize("/topic", "PUBLISH", "amqp").key,
        normalize("/topic", "PUBLISH", "mqtt").key,
    ]
    assert len(set(paths)) == 3


def test_a_custom_method_is_not_a_parameter():
    """`/v1/memos:batchGet` names an operation, not a variable.

    gRPC-gateway and Google's API guidelines put a custom method after a colon
    on the resource itself. Read as a parameter, every one of them collapsed
    into its neighbours: memos serves both `/api/v1/ai:chat` and
    `/api/v1/ai:transcribe`, and both normalized to `/api/v1/ai{}`.
    """
    chat = normalize("/api/v1/ai:chat")
    transcribe = normalize("/api/v1/ai:transcribe")

    assert chat.key.path == "/api/v1/ai:chat"
    assert transcribe.key.path == "/api/v1/ai:transcribe"
    assert chat.key != transcribe.key

    # A parameter starts the segment; a custom method follows a resource.
    assert normalize("/v1/things/{id}:cancel").key.path == "/v1/things/{}:cancel"
    assert normalize("/posts/:id").key.path == "/posts/{}"


def test_a_grpc_resource_pattern_expands_to_the_path_it_serves():
    """`{name=attachments/*}` answers on `/attachments/123`.

    The pattern body is the path, so it is expanded in place. Collapsing it to
    a bare wildcard merged every resource in memos's API into one endpoint --
    `{name=attachments/*}` and `{name=memos/*}` are not the same route.
    """
    assert normalize("/api/v1/{name=attachments/*}").key.path == "/api/v1/attachments/{}"
    assert normalize("/api/v1/{name=memos/*}").key.path == "/api/v1/memos/{}"
    assert (normalize("/api/v1/{parent=users/*}/settings").key.path
            == "/api/v1/users/{}/settings")


def test_a_double_star_in_a_resource_pattern_spans_segments():
    result = normalize("/v1/{name=shelves/*/books/**}")
    assert result.key.path == "/v1/shelves/{}/books/*"
    assert result.spans_segments is True


def test_an_expanded_pattern_meets_the_route_that_serves_it():
    """The point of expanding rather than collapsing."""
    documented = normalize("/api/v1/{name=attachments/*}", "GET")
    implemented = normalize("/api/v1/attachments/{id}", "GET")
    assert documented.key == implemented.key


def test_an_express_5_optional_group_leaves_the_path_it_certainly_serves():
    """`/user/:id{/:op}` is how Express 5 writes what used to be `:op?`.

    The braces hold a path, so the segment rules never saw a valid segment and
    the result came out as `/user/{}{/{}}`. It is the one malformed key in all
    3,195 route strings noir's fixtures produce across 33 languages.

    The group is dropped rather than expanded: the route certainly answers on
    `/user/:id`, and whether it also answers a segment deeper depends on the
    request. A documented longer form becomes a near miss, which is the right
    amount of doubt to leave behind.
    """
    assert normalize("/user/:id{/:op}").key.path == "/user/{}"
    assert normalize("/user/:id{/detail}").key.path == "/user/{}"

    # And the other brace form that holds a path is untouched by this.
    assert normalize("/api/v1/{name=memos/*}").key.path == "/api/v1/memos/{}"
