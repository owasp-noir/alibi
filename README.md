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
change to noir: every endpoint noir emits already carries the technology that
produced it, so a single scan over a tree holding code, a spec and an nginx
config comes back with all three, each labelled.

```console
$ noir -b ./mixed -f json | jq -r '.endpoints[].details.technology' | sort | uniq -c
  12 python_flask
   5 oas3
   5 nginx
```

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
$ alibi doctor                                               # view map vs. your noir build
```

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

A tool like this dies by reporting hundreds of findings on its first run. Three
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

**An absence is only evidence when the signal exists.** Noir's auth taggers
cover the frameworks they know. In a stack they do not cover, nothing carries an
auth tag, and treating that as "unauthenticated" would promote every finding and
drain the severity column of meaning. Adjustments that fire on a missing tag
require that tag to appear somewhere in the scan first.

## Rules

| Rule | Condition | Severity |
| --- | --- | --- |
| `SHADOW` | in code, not in any contract | medium |
| `PHANTOM` | in a contract, not in the code | low |

Severity then shifts on what noir's taggers found: personal data, file uploads,
no sign of authentication, or a method that changes state.

Both the view map (`views.yml`) and the rules (`rules.yml`) are data, not code.
Adding the traffic, gateway and infra rules is a matter of editing YAML.

## Status

Early. Only `code` and `doc` rules are implemented; the other three views are
mapped and collected but nothing compares them yet.

## License

MIT
