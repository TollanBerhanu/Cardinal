# Cardinal

Hands-on network-security labs that put an **attack side-by-side with its benign
twin** on the same live environment, so you can study what actually separates the
two — on the wire, in the logs, and at the detector.

Each lab is self-contained in its own directory with its own README and setup.

## Labs

### [`sql-injection/`](sql-injection/) — web-app attacks (Kathara)

A minimal [Kathara](https://www.kathara.org/) lab: a vulnerable staff-portal
webapp behind a Coraza WAF (OWASP CRS) choke point, a seeded MariaDB, a Locust
benign-traffic generator, and an attacker node with sqlmap — all watched by a
passive monitor. The one webapp exposes **SQL injection**, **XSS**, and
**insecure-deserialization** surfaces, each toggleable per request so an attack
and its byte-identical benign request share the same route.

→ See [`sql-injection/README.md`](sql-injection/README.md) and the
[`TUTORIAL.md`](sql-injection/TUTORIAL.md) walkthrough.

### [`volumetric-vs-flashcrowd/`](volumetric-vs-flashcrowd/) — DDoS vs. flash crowd (Docker Compose)

A three-network testbed (external / DMZ / protected) with a router, an IDS, and a
victim web stack. It drives two superficially similar load spikes against the same
target — a **volumetric SYN flood** and a **legitimate flash crowd** of real HTTP
traffic — so detectors can be evaluated against both attack and ground-truth benign
surge.

→ See the per-component READMEs under
[`volumetric-vs-flashcrowd/`](volumetric-vs-flashcrowd/).

## Getting started

Pick a lab and follow its README. Each lists its own prerequisites (Kathara +
Docker for `sql-injection/`; Docker Compose for `volumetric-vs-flashcrowd/`).

> These labs are intentionally vulnerable and generate attack traffic. Run them
> only in an isolated environment you control, never on a production network.
