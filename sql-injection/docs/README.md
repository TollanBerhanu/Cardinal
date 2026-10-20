# Cardinal SQLi — documentation

Documentation and reference material for the Phase-1 SQL-injection lab. The lab
itself (how to run it) starts at the root [`../README.md`](../README.md).

## Start here

| Doc | What it is |
|---|---|
| [`RUNBOOK.md`](RUNBOOK.md) | Succinct operator guide — boot, the toggle control surface, experiment recipes mapped to the reference taxonomy, and where evidence lands. |
| [`TUTORIAL.md`](TUTORIAL.md) | Full click-by-click first run: browse the portal, generate benign traffic, run the attacks (automated and by hand), find the captures. |
| [`../README.md`](../README.md) | Topology, images, prerequisites, layout. |

## Reference PDFs

| PDF | What it is |
|---|---|
| [`sqli-reference.pdf`](sqli-reference.pdf) | **The taxonomy this lab implements:** SQLi attack families (§1), defenses (§2: parameterization, input validation, WAF, RASP, DB containment, egress), and evasion techniques (§3). The map every experiment is scored against. |
| [`cardinal-testbed-blueprint.pdf`](cardinal-testbed-blueprint.pdf) | The Cardinal testbed brief — one enterprise segment carrying SQLi + XSS + insecure-deserialization under live benign traffic, with a single instrumented choke point. |
| [`experimental-evaluation-flashcrowd.pdf`](experimental-evaluation-flashcrowd.pdf) | Build guide for the **sibling** lab (volumetric-vs-flash-crowd discrimination). Kept here for reference; it is not about this SQLi lab. |
