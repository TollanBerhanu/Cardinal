# Cardinal

Cardinal is a collection of self-contained, reproducible network-security lab
environments for **evaluating attack-detection and defense mechanisms against
their benign look-alikes**. Each lab stands up a small, instrumented network in
containers, drives both a malicious scenario and a byte- or behavior-similar
legitimate scenario through the same instrumented choke point, and captures the
traffic so detectors can be scored against ground truth.

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
[`docs/TUTORIAL.md`](sql-injection/docs/TUTORIAL.md) walkthrough.

### [`volumetric-vs-flashcrowd/`](volumetric-vs-flashcrowd/) — DDoS vs. flash crowd (Docker Compose)

A three-network testbed (external / DMZ / protected) with a router, an IDS, and a
victim web stack. It drives two superficially similar load spikes against the same
target — a **volumetric flood** and a **legitimate flash crowd** of real HTTP
traffic — so detectors can be evaluated against both attack and ground-truth benign
surge. The IDS node sits inline between the DMZ and protected segments and captures
full-packet pcaps at two taps; scenario phase transitions are logged so alerts can
be aligned against ground truth.

→ See the per-component READMEs under
[`volumetric-vs-flashcrowd/`](volumetric-vs-flashcrowd/), starting with
[`flash-crowd/`](volumetric-vs-flashcrowd/flash-crowd/README.md) and
[`ids/`](volumetric-vs-flashcrowd/ids/README.txt).

## Prerequisites

- **Docker** (Docker Desktop, or Docker Engine on Linux/WSL) with Linux
  containers.
- **[Kathara](https://www.kathara.org/download.html)** for the `sql-injection`
  lab (`pip install kathara` or `brew install kathara`).

Each lab builds its own images and brings its own topology up; follow the lab's
README for the exact boot sequence.

## Layout

```
sql-injection/              Kathara lab (WAF + webapp + DB + benign traffic + monitor)
  docs/                     RUNBOOK, TUTORIAL, and reference material
volumetric-vs-flashcrowd/   Docker Compose testbed (router, IDS, victim)
  flash-crowd/              Legitimate-surge load generator
  DDoS/                     Attack-traffic generator
  ids/                      Inline Suricata + tcpdump capture node
  orchestration/            Host-side scenario orchestrators (ground-truth timeline)
  dataset/                  Captured pcaps and resource-usage metrics
  scenario-logs/            Per-run logs and Locust stats
```

## Scope

These are **research and teaching environments for authorized use only.** Every
lab runs entirely within its own isolated container networks against targets it
provisions itself. Run them only on infrastructure you own or are authorized to
test; don't point any component at systems outside the lab.
