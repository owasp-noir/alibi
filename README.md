# alibi

Cross-check the views of your attack surface and find the endpoints that cannot
corroborate each other.

An endpoint should be able to account for itself. It is in the code, so a
contract should describe it. It is in the contract, so something should
implement it. It takes real traffic, so it had better exist somewhere. When one
view knows about an endpoint and the others do not, that gap is the finding.

alibi runs [OWASP noir](https://github.com/owasp-noir/noir), reads its JSON, and
compares the views against each other.

## Why this is a separate tool

Noir already reads five independent views of the same surface:

| View | Read from |
| --- | --- |
| **code** | 200-plus analyzers across 33 languages |
| **doc** | OpenAPI, RAML, WSDL, GraphQL SDL, AsyncAPI, gRPC, Smithy, TypeSpec, OData, OpenRPC |
| **traffic** | HAR, mitmproxy, Burp, Caido, ZAP, Postman, Insomnia, Bruno, `.http` |
| **gateway** | nginx, Apache, Envoy, Kong, Traefik, APISIX, Caddy, Istio, Kubernetes Ingress and Gateway API |
| **infra** | Terraform, CloudFormation, CDK, Serverless, Vercel, Netlify, Wrangler, Azure Functions, Kamal |

What it does not do is compare them. That is the whole job here, and it needs no
change to noir — alibi runs it once per view and joins the results.

The per-view part matters. Noir deduplicates by `(method, url)` across every
analyzer, so a Flask route and an OpenAPI path spelled identically collapse into
one endpoint carrying one technology. That is right for a discovery tool — it is
one endpoint — but it erases the corroboration this tool is built to measure,
and it erases it in the worst possible direction: the better two views agree,
the more of them vanish. Casdoor scans as 372 code endpoints and 9 documented
ones; scan its `swagger/` directory alone and the specification has 235.

`--only-techs` restricts the detector pool, so one scan per view keeps each one
whole. Which technology speaks for which view is `views.yml`; which
technologies exist is whatever `noir list techs` reports.

alibi parses no API formats of its own. Its only input is noir's JSON.

## Install

Requires [noir](https://github.com/owasp-noir/noir) on `PATH`.

```console
$ uv tool install noir-alibi     # or: pipx install noir-alibi
$ alibi scan ./my-service
```

## Use

```console
$ alibi scan ./service ./contracts ./captures/prod.har
```

Every path is one noir scan. Point it at whatever you have — the views that are
missing simply switch their rules off rather than flooding the report.

```
alibi  ·  1 source  ·  22 endpoints

  code 12   doc 5   gateway 5

SHADOW  Shadow API -- Implemented, but no contract describes it
  12 findings

  high     PUT     /create_record   app.py:52
           changes state rather than reading it
  high     DELETE  /delete_record   app.py:66
           changes state rather than reading it
  medium   GET     /cookie          app.py:31
```

```console
$ alibi scan ./service ./contracts -f json --fail-on high    # for CI
$ alibi scan ./service ./contracts -f sarif                  # for GitHub code scanning
$ alibi doctor                                               # view map vs. your noir build
```

Findings on their own say where the views disagree today. `--snapshot` records
each scan so the next one can say what moved:

```console
$ alibi scan ./service ./contracts --snapshot    # into .alibi/snapshots.db
$ alibi history                                  # new and resolved since the last scan
```

```
alibi history  ·  .alibi/snapshots.db  ·  4 scans

  2026-08-30T09:12:04Z  compared against  2026-08-29T18:03:11Z

NEW  the previous scan did not have these
  1 finding

  high     SHADOW   DELETE  /admin/purge
           endpoint first seen in code 2026-08-12T11:40:02Z
```

That last line is the part worth reading. A shadow API on a route that arrived
with it is a documentation step somebody skipped; one on a route that has been
in the code since August means a contract stopped covering it.

## How endpoints are matched

Noir keeps each framework's own route syntax rather than inventing a common one,
so the same endpoint arrives spelled several ways:

```
python_flask   /api/users/<int:user_id>
aiohttp        /users/{id}
java_spring    /api/catalog/{id}
oas3           /v1/pets/{petId}
rails          /posts/:id
nginx          /admin/.*
```

The rule that makes these comparable: **a path parameter's name is not part of
its identity.** `{petId}` and `<int:user_id>` describe the same slot; only its
position and whether it spans a `/` matter. Names are kept as evidence and
reported, but never reach the key.

Findings say how the match was made:

| Grade | Meaning |
| --- | --- |
| `G1` | the spellings already agreed |
| `G2` | they agree once parameter syntax is normalized |
| `G0` | only one view has it — nothing was matched |

## What keeps it honest

A tool like this dies by reporting hundreds of findings on its first run. Five
things push back:

**Rules do not fire without both views.** Scan a codebase with no contracts
anywhere and every endpoint technically qualifies as an undocumented shadow API.
Those findings say nothing except that you did not supply any documentation, so
a rule only runs when every view it reasons about was actually in the scan. The
report names the rules that sat out.

**Near misses are reported as doubt, not as findings.** "In code, not in the
docs" is indistinguishable from "in both, but alibi failed to line them up." So
an endpoint that lands in one view is checked against the others for a near
miss — same path with a different verb, or one segment apart where one side has
a parameter and the other a literal. Findings carrying a near miss are demoted
and flagged for review. That count sits next to the totals, because every
finding is only as trustworthy as it is small.

**Views that never met are one diagnostic, not hundreds of findings.** Argo CD
registers `/api` in Go and documents 198 paths beneath it, so its code and its
specification share not one endpoint. Read literally that is 58 shadow APIs and
198 phantom contracts, none of them real. Zero corroboration between two
populated views means the comparison did not work — a mount point standing in
for the routes beneath it, or a stack noir could not read — so the rules are
held back and the reason is printed instead. Paths that turn out to have many
endpoints from other views beneath them are labelled as probable mounts.

**A missing view and an empty one mean opposite things.** Noir reports what it
could not read, and alibi prints that above the findings. NetBox ships a 12.35MB
OpenAPI document with 308 paths; noir skips it for exceeding its file-size cap,
and without that report alibi states the project documents nothing — not merely
incomplete, but the wrong answer stated confidently.

**An absence is only evidence when the signal exists.** Noir's auth taggers
cover the frameworks they know. In a stack they do not cover, nothing carries an
auth tag, and treating that as "unauthenticated" would promote every finding and
drain the severity column of meaning. Adjustments that fire on a missing tag
require that tag to appear somewhere in the scan first.

## Rules

| Rule | Condition | Severity |
| --- | --- | --- |
| `ORPHAN` | taking real requests, absent from the code | high |
| `LIVE_UNDOC` | taking real requests, described by no contract | high |
| `SHADOW` | in code, not in any contract | medium |
| `DANGLING` | a gateway rule that reaches nothing implemented | medium |
| `DRIFT` | declared for deployment, missing from the code | medium |
| `PHANTOM` | in a contract, not in the code | low |
| `UNEXPOSED` | implemented, but no gateway rule reaches it | low |
| `COLD` | implemented, never seen taking a request | info |

Severity then shifts on what noir's taggers found: personal data, file uploads,
no sign of authentication, or a method that changes state.

Both the view map (`views.yml`) and the rules (`rules.yml`) are data, not code.

### Gateways are not endpoint lists

One `location /api/` stands for everything beneath it, so gateway and
infrastructure rules answer *does this reach that endpoint* rather than *does
this contain it*. Compared as sets, every prefix rule looks like a route nobody
implemented and every implemented route looks unreachable.

Coverage is deliberately generous. Noir reports the path a rule matches but not
whether it matches as a prefix or exactly (`location = /x`, an Ingress
`pathType: Exact`), so exactness cannot be recovered — and treating every rule
as a prefix suppresses findings rather than inventing them.

The report says how much of the code each routing view reaches, because whether
"34 endpoints no gateway reaches" is real depends on whether that config is the
one fronting the service. No threshold separates those honestly: Argo CD's e2e
test fixture reaches 39% of its code and NetBox's real config reaches 100%.

### Traffic has to have been watched

A HAR capture records requests that happened. A Postman collection records
requests somebody meant to make. `ORPHAN`, `LIVE_UNDOC` and `COLD` all reason
about what ran, so they require a view somebody actually watched and say so
when they sit out.

### Non-web surface stays out

Noir reports CLI arguments, Kafka topics and mobile deep links in the same
list. `cli://gitops-engine/agent` flattened into HTTP becomes `/agent` — it
collides with any web route of that name and gets asked whether a gateway
routes to it. The protocol belongs to the endpoint's identity; `http` and
`https` are one space and everything else keeps its own.

## Suppression

Some gaps are the intended state. Put an `.alibi.yml` beside the source:

```yaml
ignore:
  - path: "^/internal/"
    why: internal-only admin surface
  - rule: UNEXPOSED
    path: "^/debug/"
    why: not fronted by the gateway in this repo
```

Or pass `--ignore REGEX` for a one-off. Suppressed findings are counted and the
count is printed — a tool that quietly drops findings is worse than one that
prints too many, because there is no longer any way to tell what it withheld.

## Status

Early, but all five views are compared.

Measured against five repositories:

| Repository | code | doc | corroborated | findings | near misses | |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| casdoor | 372 | 235 | 230 | 147 | 19 | compared |
| flipt | 2 | 42 | 0 | 0 | 0 | held back |
| authentik | 231 | 1193 | 0 | 0 | 12 | held back |
| argo-cd | 59 | 198 | 0 | 0 | 14 | held back |
| netbox | 855 | 0 | — | 0 | 2 | no contract found |

Casdoor is the case where both views arrive at route level, and there **230 of
its 235 documented endpoints matched the code — 97.9%, with no path
normalization failures at all.** All 19 near misses were the same path under a
different verb, which is noir registering every method on a Go catch-all
handler, not a matching problem. That is the number that says whether this
approach works.

The other four are held back, and each for a real reason: NetBox ships no
specification noir recognises; Argo CD registers `/api` in Go while documenting
198 paths beneath it; noir reads no Django routes in authentik and picks up an
unrelated Rust component instead. Reporting 1424 findings on authentik would
have been easy and worthless.

## License

MIT
