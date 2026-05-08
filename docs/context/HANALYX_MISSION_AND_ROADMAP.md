# Hanalyx — Long-Term Mission and 18-Month Trust Roadmap

**Status:** Founding document, draft v1
**Scope:** Long-term mission, vision, and the 18-month roadmap for investing in the seven trust moats that AI cannot replicate.
**Companion documents:**
- `HANALYX_18_MONTH_STRATEGY.md` — tactical strategy, 90-day plan, go-to-market
- `AI_DEFENSIBILITY.md` — why Hanalyx becomes more valuable as AI improves

---

## Mission

**No Linux change should ever be unsafe, unauditable, or unreversible — whether a human or an AI made it.**

We exist to be the safety rail that every critical Linux infrastructure change runs through before it touches production. Compliance remediation is our first market. It is not our final market.

## Vision (5-year)

In five years, Hanalyx is the canonical rollback-safe Linux state engine. When a federal contractor needs to pass a STIG audit, they run Kensa. When an SRE at a commercial company needs to change a kernel parameter across 5,000 hosts without risking a 3 AM incident, they run Kensa. When an autonomous AI agent needs to modify a production configuration and prove to a human reviewer that the change is reversible, it runs Kensa underneath.

We are not a compliance scanner. We are the Linux production safety layer. Compliance is the first application of a more general platform. Every subsequent application — drift detection, safer configuration management, AI agent infrastructure, regulated workload automation — is built on the same engine, sold to different buyers, under the same brand family.

We are an open-source company. Our code is auditable because the customers we serve cannot trust a black box to modify their production systems. Our moat is not the code itself but the track record, the certifications, the community, the liability we absorb, and the canonical status of being the reference implementation of a category we create.

---

## The Seven Trust Moats

The `AI_DEFENSIBILITY.md` analysis identified seven categories of value that AI improvement makes more scarce, not less. This roadmap organizes our 18-month investments around those seven moats, because each one is a compounding asset that a well-funded AI-accelerated competitor cannot shortcut.

1. **Track Record** — customer-months of production use without incident
2. **Auditor Relationships** — trust networks with Big 4 audit firms and federal ATO reviewers
3. **FedRAMP Authorization** — the 18-month human-bound process that unlocks tier-1 federal sales
4. **Community** — the social graph around the open-source project
5. **Liability Insurance & Contractual Trust** — the commitments we make that AI companies cannot
6. **Canonical Upstream Status** — being the reference implementation of a named category
7. **Long-Tail Production Experience** — knowledge of failure modes that don't exist in any training dataset

Each moat has (a) a target outcome at month 18, (b) a KPI we track monthly, and (c) concrete quarterly investments. The sections below are the core of this document.

---

## Moat 1: Track Record

**The asset:** Production customer-months without a Kensa-caused incident.

**Why it matters in an AI world:** AI can generate rollback code in minutes. It cannot generate six months of a customer running that code in production without breakage. Track record is pure calendar time — the one resource no amount of AI leverage can compress.

**Target outcome at month 18:** At least 20 cumulative production customer-months across 5+ distinct fleets, zero Kensa-caused production incidents, one public post-mortem of a failure mode we caught and fixed.

**KPI:** Cumulative production customer-months. Tracked monthly.

### Investments by quarter

**Q1 (months 0-3):**
- Land 3 lighthouse customers (free, in exchange for deployment and feedback).
- Instrument every rule execution with anonymized telemetry (opt-in) capturing: mechanism type, pre-state captured (yes/no), remediation outcome (success/fail/rollback), rollback outcome (success/fail), host OS version. This is our production dataset.
- Define the "incident" metric explicitly: any Kensa operation that required customer intervention to recover from. Zero tolerance.

**Q2 (months 3-6):**
- Convert at least 1 lighthouse to a signed paid contract. Revenue matters less than the reference.
- Publish the first **"State of Production Rollback" report** — internal-only at first, then external at Q4 — summarizing what we've learned from the telemetry. Positions us as the people who know what actually breaks in production.
- First post-mortem: find a failure mode in a lighthouse deployment, fix it, write it up publicly. **The post-mortem itself becomes a trust asset.**

**Q3 (months 6-9):**
- Target: 5 production customers, 10+ customer-months accumulated.
- Offer a written production SLA to paying customers: "If a Kensa operation breaks your production and we can't roll it back, we credit 3 months of service." This is a commitment AI companies cannot make.
- Begin tracking the MTTR (mean time to remediate) metric per mechanism — this becomes the factual basis for future marketing claims.

**Q4 (months 9-12):**
- 10+ active production customers, 20+ customer-months.
- Publish **first public production report** with anonymized statistics: "In 6 months across 10 customer fleets, Kensa applied X changes, rolled back Y, and caused zero production incidents." This is the single most powerful marketing artifact we can produce, and it only exists if we actually achieved it.

**Q5-Q6 (months 12-18):**
- 15+ active production customers, 40+ customer-months.
- Second public production report. By now the narrative is "Kensa has touched X thousand hosts in production for Y months without a single customer-reported incident." That sentence, printed on every marketing page, is worth more than any competitive feature comparison.

---

## Moat 2: Auditor Relationships

**The asset:** Direct trust relationships with the Big 4 audit firms and federal ATO reviewers who evaluate Kensa evidence.

**Why it matters in an AI world:** AI cannot introduce itself to a partner at Deloitte. The human trust network between vendor and auditor is the most unreplicatable asset in regulated markets, and it compounds over years.

**Target outcome at month 18:** Formal briefings completed with at least 3 Big 4 audit practices, at least one Big 4 auditor citing Kensa evidence format in a report, at least 2 federal ATO reviewers who have personally reviewed Kensa evidence.

**KPI:** Number of named auditors briefed. Tracked quarterly.

### Investments by quarter

**Q1 (months 0-3):**
- Map the target list: 15-20 named individuals at Deloitte, PwC, KPMG, EY, and regional firms specializing in federal compliance (Schellman, Coalfire, A-LIGN).
- Leverage the founder's federal network to secure 3 informal introductions. Goal is not a sale — it is a 30-minute conversation explaining the rollback-safe evidence model and asking for feedback on the format.
- Draft the **"Evidence Format White Paper"** — a 10-page document explaining what Kensa evidence contains, why it's auditor-grade, and how it improves on existing scanner output. This becomes the leave-behind for every auditor conversation.

**Q2 (months 3-6):**
- Complete 6-8 auditor conversations. Iterate on the evidence format based on what auditors actually want to see. Ship those iterations in Kensa.
- Begin **OSCAL export work**. OSCAL is the NIST-sponsored standard for machine-readable compliance evidence. Auditors are starting to ask for it. Shipping OSCAL export is a direct signal to the audit community that we are serious.

**Q3 (months 6-9):**
- Submit Kensa evidence format to at least one audit firm's internal technical review. Goal: get our format into their "approved evidence formats" list, even informally.
- Sponsor or speak at one audit-adjacent conference: ISACA CACS, AICPA ENGAGE, or the FedRAMP Marketplace Summit. Audience is auditors and compliance officers, not engineers.
- First federal ATO reviewer briefing. Target: an agency that has worked with the founder in the past.

**Q4 (months 9-12):**
- Have at least one auditor formally reference Kensa in a customer engagement. This is the moment we stop being a vendor pitch and start being part of the audit ecosystem.
- Publish a joint blog post with an auditor (even a small firm) titled something like "What makes compliance evidence auditable — a conversation with [Auditor]." This is content that only exists because of the relationships we built.

**Q5-Q6 (months 12-18):**
- 3+ Big 4 relationships active. One joint webinar or published case study.
- Auditor feedback is now a direct input into our rule roadmap. When an auditor says "we wish Kensa covered X," we ship it the same quarter. That responsiveness is itself a trust asset.

---

## Moat 3: FedRAMP Authorization

**The asset:** FedRAMP Moderate authorization for OpenWatch as a hosted service (or for Kensa as a continuously-monitored tool).

**Why it matters in an AI world:** FedRAMP is an 18-month human-bound process involving a Third-Party Assessment Organization (3PAO), continuous monitoring documentation, agency sponsorship, and policy review. Every month of delay is a month of structural lead we are giving away. **AI does not compress this timeline. A competitor who starts six months later is always six months behind.**

**Target outcome at month 18:** FedRAMP Moderate authorization achieved, or at minimum "In Process" status on the FedRAMP Marketplace with a named agency sponsor.

**KPI:** Stage of FedRAMP process. Tracked monthly.

### Investments by quarter

**Q1 (months 0-3):**
- **Start immediately.** This is the single highest-leverage action in the entire 18-month plan from an AI-defensibility standpoint. Every day of delay is a day of moat we are not building.
- Complete FedRAMP **Readiness Assessment (RA)** with a qualified 3PAO. Typical cost: $40K-80K. This is the largest single cash expenditure in Year 1 and it is non-negotiable.
- Identify agency sponsor candidates from the federal network. Sponsorship can happen in parallel with readiness work but must be secured before 3PAO assessment begins.
- Begin gap analysis: which NIST 800-53 Rev 5 Moderate baseline controls does OpenWatch currently meet, which need implementation. Use AI heavily for the documentation generation.

**Q2 (months 3-6):**
- Close gaps identified in RA: SSO (SAML/OIDC), FIPS 140-3 validated cryptography in OpenWatch, audit logging expansion, incident response plan, continuous monitoring procedures.
- Finalize agency sponsor.
- Formal kickoff with 3PAO for security assessment.

**Q3 (months 6-9):**
- 3PAO security assessment in progress. Respond to findings in real-time.
- Draft System Security Plan (SSP), Plan of Action and Milestones (POA&M), Continuous Monitoring Plan.
- **Listing on FedRAMP Marketplace as "In Process"** — this alone is a marketing asset. Federal buyers will engage with "In Process" vendors.

**Q4 (months 9-12):**
- Submit SAR (Security Assessment Report) to sponsor agency.
- Remediate findings. This is the phase most vendors underestimate — it typically takes 3-6 months of iterative remediation.

**Q5-Q6 (months 12-18):**
- Agency Authority to Operate (ATO) issued. Transition to FedRAMP PMO review for marketplace listing as "Authorized."
- **If authorization lands by month 18:** we are one of a small number of compliance automation vendors with FedRAMP Moderate status, and every federal sale becomes materially easier.
- **If authorization slips to month 20-24:** that is normal. The fact that we are In Process and have a sponsor is still a massive competitive differentiator.

---

## Moat 4: Community

**The asset:** The social graph of humans who spend attention on the Kensa and OpenWatch projects.

**Why it matters in an AI world:** AI can fork code. AI cannot fork a community. When AI-generated knockoffs flood the market, customers will ask "which project has real humans behind it," and the answer is determined by GitHub stars, Discussions activity, external contributors, and whether anyone has ever written about the project unprompted.

**Target outcome at month 18:** 2,000+ GitHub stars across Kensa + OpenWatch, 50+ distinct external contributors (rules, fixes, integrations), 5+ third-party blog posts or talks about the project we did not commission, active Discussions forum with weekly activity.

**KPIs:**
- GitHub stars (Kensa + OpenWatch combined)
- Distinct external contributors (all-time, excluding founders)
- External mentions (blogs, talks, podcasts) not authored or commissioned by Hanalyx

### Investments by quarter

**Q1 (months 0-3):**
- Rewrite both GitHub READMEs to foreground the rollback engine and category, not the compliance framing.
- Establish **weekly blog cadence** on the rollback engine. Not compliance content. Engineering content: "How we capture pre-state for sshd config changes," "Why rollback-safe automation is harder than it looks," "The 20% of Linux mechanisms you should never try to rollback automatically."
- Ship GitHub Discussions with a visible maintainer presence: we personally respond to every issue, every question, every PR within 24 hours during this phase.
- Seed the first 10 GitHub stars through the founder's network. Do not buy stars. Ask people we know to look at the project honestly.

**Q2 (months 3-6):**
- **First public conference talk.** Target: USENIX LISA, SCaLE, FOSDEM devroom, or a regional DevOps meetup. Talk title is about rollback-safe automation as a primitive, not about compliance. Goal: 100 engineers in a room who remember the project.
- Launch a **public contributor onboarding guide**. Document how to write a Kensa rule, how to add a capture handler, how to add a rollback handler. The existence of this guide is itself a community signal.
- First external contribution accepted — even a typo fix. Celebrate it publicly.

**Q3 (months 6-9):**
- Target: 500 GitHub stars, 10 external contributors.
- **Launch a "rollback-safe automation" category hub** on the Hanalyx website. Not a product page — a category page. List our project alongside related tools (even competitors) and explain the landscape. This positions us as the category's narrator, not just a participant.
- Second conference talk at a bigger venue.
- Invite one community member to co-author a blog post about their use case.

**Q4 (months 9-12):**
- Target: 1,000 GitHub stars, 25 external contributors.
- **First Hanalyx community event.** Virtual meetup, 1 hour, 5 speakers (including at least 2 non-founders). Record it. Publish it. This is the first proof that the community exists outside the founders' heads.
- Establish a public roadmap and a public rule request process. Community input on direction is a stronger trust signal than top-down development.

**Q5-Q6 (months 12-18):**
- Target: 2,000+ GitHub stars, 50+ external contributors.
- **Third-party validation:** at least 5 blog posts, podcast mentions, or conference talks about Kensa that we did not commission. This is the hardest metric to manufacture and the most meaningful.
- Begin accepting small donations / corporate sponsorships for the open-source projects via GitHub Sponsors or Open Collective. Not for revenue — as a signal that the project is important enough for third parties to fund.

---

## Moat 5: Liability Insurance & Contractual Trust

**The asset:** The commitments we make to customers that an AI company structurally cannot.

**Why it matters in an AI world:** Someone has to be legally and practically responsible when a rollback fails and breaks prod. AI vendors explicitly disclaim this responsibility in their EULAs. Enterprise customers — especially regulated ones — will pay a premium for a vendor who contractually absorbs the risk.

**Target outcome at month 18:** $10M Errors & Omissions (E&O) coverage, cyber liability coverage, a written production SLA, and at least one signed customer contract that includes Hanalyx-authored indemnification language.

**KPIs:**
- E&O coverage amount
- Number of customers under a signed SLA
- Number of customer contracts with indemnification clauses

### Investments by quarter

**Q1 (months 0-3):**
- Begin insurance broker conversations. Start cheap: a basic E&O policy for a pre-revenue software company is typically $3K-8K/year for $1M of coverage. This is not the final state, but it establishes insurability.
- Draft the **Hanalyx Production Safety Commitment** — a public document on the website articulating what we will and won't stand behind. This document is a marketing asset *and* a contractual foundation.

**Q2 (months 3-6):**
- Increase E&O coverage to $2M-5M as customer contracts start to reference it.
- First customer contract with Hanalyx-authored MSA (Master Service Agreement) template, including indemnification language for rollback failures up to the contract value.
- Begin drafting a **Production SLA template** with specific commitments: "Kensa will not leave a customer host in an unrecoverable state. If it does, we credit [X]."

**Q3 (months 6-9):**
- First cyber liability policy. Federal customers will require it.
- SLA template finalized and offered to all paying customers. Post the generic version publicly as a trust signal.

**Q4 (months 9-12):**
- $5M E&O coverage. Cyber liability in place.
- Publish a **"What We Stand Behind"** page on the website listing the specific commitments — SLA credits, response times, insurance coverage amounts. Competitors cannot easily match this without actually committing.

**Q5-Q6 (months 12-18):**
- $10M E&O coverage. This is the level enterprise procurement expects for production-mutating software.
- At least 5 customers under signed SLAs with active indemnification language.
- The phrase **"Hanalyx is the only rollback-safe Linux automation vendor that stands behind its rollback with a written production SLA"** becomes a concrete, defensible marketing claim.

---

## Moat 6: Canonical Upstream Status

**The asset:** Being the reference implementation of a named category.

**Why it matters in an AI world:** AI makes forks cheap. In a world of 50 AI-generated Kensa knockoffs, the question "which is the real one" becomes critical. The canonical upstream is the one with the blog, the maintainers, the conference talks, the Wikipedia entry, the category name, and the auditor relationships. It is the one journalists call for quotes.

**Target outcome at month 18:** The phrase "rollback-safe Linux automation" has a Wikipedia stub (written by someone else), at least 10 external articles reference the category, and Hanalyx is cited as the canonical implementation in at least 3 of them.

**KPIs:**
- Number of external references to "rollback-safe Linux automation" or equivalent category phrase
- Search volume for the category phrase (Google Trends, if measurable)
- Number of external references that cite Hanalyx/Kensa by name

### Investments by quarter

**Q1 (months 0-3):**
- Coin the category name publicly. Top candidates: "rollback-safe Linux automation," "closed-loop state enforcement," "production-safe configuration management." Pick one, commit to it, use it in every blog post and every talk.
- Launch the weekly blog cadence (already listed under Community — this is the same investment, different moat).
- Publish a foundational piece: **"What is rollback-safe Linux automation?"** This becomes the reference article the rest of the internet links to.

**Q2 (months 3-6):**
- Get the category phrase into at least 3 external contexts: a podcast mention, a conference talk we don't deliver, a Hacker News discussion.
- Submit a talk to a major conference (KubeCon, DevOps Enterprise Summit, USENIX LISA) specifically framed around the category, not around the product.

**Q3 (months 6-9):**
- **Write the definitive long-form piece** (5,000-8,000 words) on rollback-safe automation as a category. Treat this as a tentpole content asset. Publish it on the Hanalyx blog and cross-post to relevant venues.
- Begin pitching tech journalists (The New Stack, The Register, DevClass, LWN) on the category angle, not the product angle.

**Q4 (months 9-12):**
- Target: first external article about the category that is not written by us. Even a small blog post on dev.to.
- Launch a **public category wiki / knowledge base** (on our site or GitHub) that explains the landscape: what existing tools do and don't do, what the category requires, which projects are in it. Being the landscape's cartographer is a form of canonical status.

**Q5-Q6 (months 12-18):**
- Target: Wikipedia stub exists (written by someone else, but we can be the primary source).
- 10+ external references to the category in public discourse.
- At least one analyst firm (Gartner, Forrester, IDC, or GigaOm) acknowledges the category in a report. This is hard but high-leverage.

---

## Moat 7: Long-Tail Production Experience

**The asset:** Knowledge of failure modes that only emerge in real customer environments and that are not in any AI training dataset.

**Why it matters in an AI world:** AI is excellent at the 80% of cases that appear in training data. The 20% that actually breaks production — the weird distro variants, the non-standard PAM modules, the kernel versions nobody else supports, the SELinux policies that conflict with systemd drop-ins — is where real production automation lives or dies. That 20% is not in the training data because nobody blogged about it. The only way to know it is to encounter it in a customer environment and fix it.

**Target outcome at month 18:** Kensa supports production deployments across at least 8 distinct OS/version combinations with documented handling of at least 50 specific failure modes that are not found in the public documentation of any competing tool.

**KPIs:**
- Number of distinct OS/version combinations with production customers
- Number of documented failure modes in our internal knowledge base
- Number of failure modes we have written up publicly (the ones we can share)

### Investments by quarter

**Q1 (months 0-3):**
- Establish an **internal "failure mode log"** — a running document of every weird thing we encounter in customer environments. Even pre-customer, log every failure we find in our own test environments.
- Target OS coverage: RHEL 8, RHEL 9, AlmaLinux 9, Rocky 9. Four combinations in production-grade test environments.

**Q2 (months 3-6):**
- First lighthouse customer deployments. **Treat every customer deployment as a field research expedition.** The goal is not just to make it work — it is to document what was weird and why.
- Target: 8 failure modes logged from real environments. Each one has a code fix, a test case, and a write-up.
- Add Ubuntu 22.04 LTS and 24.04 LTS to supported environments. Partial support is fine — focus on the top 50 rules by customer demand.

**Q3 (months 6-9):**
- Target: 20 failure modes logged. Begin publishing the non-sensitive ones publicly as "Lessons from the field" posts. These are the highest-trust content pieces we can produce because they prove we have real customers with real problems.
- Add RHEL 10, Oracle Linux 9, SUSE 15.
- **First failure mode attributed to an AI-generated competitor** — if we find a case where a naive implementation would have broken prod and we caught it, write it up publicly. This is the clearest possible demonstration of the moat.

**Q4 (months 9-12):**
- Target: 35 failure modes logged, 15 published publicly.
- 8 distinct OS/version combinations in production.
- Begin building an **automated regression suite** that runs every rule against every supported environment on every commit. This is the AI-leveraged way to scale long-tail experience into something repeatable.

**Q5-Q6 (months 12-18):**
- Target: 50+ failure modes logged, 25+ published publicly.
- The published "Lessons from the field" series becomes its own reference work. **Competitors will link to it because it's the best information available on Linux production automation edge cases.**
- When a new customer asks "does Kensa work on our specific environment," the answer is increasingly "we've seen it, here's how we handle it."

---

## Quarterly Milestones Summary

| | Track Record | Auditors | FedRAMP | Community | Liability | Canonical | Long-Tail |
|---|---|---|---|---|---|---|---|
| **Q1** | 3 lighthouses | 3 briefings | RA kickoff | Weekly blog, 100 stars | $1M E&O | Category coined | 4 OS, log started |
| **Q2** | 1 paid, first post-mortem | 6-8 meetings, OSCAL work | Gap closure, sponsor secured | First talk, contrib guide | $2-5M E&O, MSA template | 3 external mentions | 8 failure modes |
| **Q3** | 5 customers, SLA offered | 1 audit firm approval | In Process listing | 500 stars, 10 contributors | Cyber liability added | Longform published | 20 modes, 6 OS |
| **Q4** | 10 customers, first public report | Joint content with auditor | SAR submitted | 1,000 stars, first event | $5M E&O, SLA template public | First external article | 35 modes, 8 OS |
| **Q5** | 15 customers | 3 Big 4 active | Remediation phase | 1,500 stars | 3 customers under SLA | Analyst acknowledgment push | 45 modes |
| **Q6** | 20+ customers, 40+ cust-months | Joint webinar or case study | ATO issued (or In Process) | 2,000 stars, 50 contributors | $10M E&O, 5 SLAs signed | Wikipedia stub, 10 refs | 50+ modes, 25 public |

---

## How We Use AI to Build the Things AI Does Touch

**AI drafts. Humans reason.** That is the entire policy in four words. Everything else is operational detail.

### Why Kensa is critical software

Kensa is not critical in the sense that every company must run it to stay alive. It is critical in a different and more specific sense: **using it requires trust, because it modifies production.** A buyer installing Kensa grants it permission to change the state of systems they cannot afford to lose. That kind of criticality — the criticality of the trust relationship between tool and operator — is what defines our engineering discipline. It is why we can use AI aggressively across the codebase and still credibly sell human judgment as the product. The question is never "is AI allowed to touch this code" — it is "has a human personally reasoned about what this code does in production."

A team of 2 cannot execute this roadmap without extreme AI leverage. We use AI for everything. We do not use AI as a substitute for reasoning about production failure modes. The commitments below distinguish the two.

### AI-first, standard review

The following work is drafted by AI and reviewed by a human for accuracy and voice. Speed is the goal; human attention is preserved for higher-stakes work.

1. **Rule YAML authoring** — AI drafts the rule, a human reviews the detection logic and decides whether the rule is worth shipping.
2. **Documentation** — release notes, changelogs, API docs, blog posts, customer emails, onboarding guides, contributor guides.
3. **Boilerplate code** — tests, fixtures, database migrations, CRUD endpoints, React components, configuration loaders.
4. **FedRAMP paperwork** — SSP, POA&M, CMP, response-to-findings, continuous monitoring reports. Hundreds of pages of structured text that AI handles well.
5. **Support triage** — incoming GitHub issues and support requests are tagged, categorized, and draft-responded by AI. Human approval before anything ships to a customer.
6. **Internal post-mortems** — telemetry-driven drafts, human review and editorial decisions before publication.

### Risk-weighted review for engine code

The rollback, capture, and remediation engine is where production risk lives. Not all engine code carries the same risk, and review ceremony is weighted accordingly:

| Component | Blast radius if wrong | Review requirement |
|---|---|---|
| **Rollback handlers** | Production stays broken. Highest severity. | Human designs the failure-mode matrix first (what can go wrong, what state must be restored). AI drafts against that matrix. Two-human review. Ephemeral-environment integration test of the actual rollback path is mandatory before merge. |
| **Remediation handlers** | Wrong change applied to production. | Human designs the change + validation plan. AI drafts. One-human review. Integration test mandatory. |
| **Capture handlers** | Missing state means rollback may be incomplete. Medium severity. | AI drafts. Human reviews with a "what state might we be missing" checklist. Test against at least one concrete failure case. |
| **Validation logic** | We think something worked that didn't. Medium severity. | AI drafts. Human reviews. Covered by the integration test for the change itself. |
| **Dry-run paths** | User confusion only. Low severity. | AI-first, standard review. |
| **Schema and framework mappings** | Metadata correctness. Recoverable. | AI-first, domain review. |

The table is not a binary "AI allowed / AI not allowed." It is a statement of where human attention is most valuable. Rollback handlers get the heaviest ceremony because that is where the moat actually lives. Dry-run paths get minimal ceremony because they are low-stakes. Treating every piece of engine code the same wastes our scarcest resource: human reasoning about production failure modes.

### The failure-mode analysis commitment

**Every production-mutating change ships with a human-authored failure-mode analysis in the PR description.** The analysis answers three questions:

1. What could this change do wrong in production?
2. What state is captured before the change, and is it sufficient to restore the system if the change or its validation fails?
3. What real-world edge case is this change *not* safe for, and is that edge case documented and gated?

The human writes that analysis. AI may help structure it. AI may not be the final reasoner. The analysis is checked into the repository as part of the permanent PR history, producing a verifiable audit trail: **for every production-mutating change in Kensa's history, a human personally reasoned about failure modes and signed off.** This commitment is defensible in marketing, in customer contracts, in insurance applications, and in FedRAMP documentation — and it is verifiable by anyone who reads the repository.

This is a stronger commitment than "no AI in the engine" because it is (a) actually true, (b) verifiable from the git history, and (c) consistent with using AI aggressively for everything else. Competitors who want to match it must adopt the discipline, not just the tooling.

### The human-review commitment

The failure-mode reasoning skill is perishable. If review of AI-authored code degrades into rubber-stamping, the deep intuition about Linux production failure modes decays even when the founders are still nominally signing off on changes. The mitigation is not that founders write the code themselves — it is that they read every line of it with the same scrutiny they would apply to a hostile pull request, and they exercise the resulting code under real-host failure conditions before it ships.

**The founders will conduct rigorously tests, and review the application. The Kensa AI team and collaborator will write all of the application code. The founders commit and consider human review of the code is non-negotiable. The day we stop is the day our failure-mode reasoning starts decaying.**

A practical rule of thumb: if in any given week the founders have merged AI-authored engine, capture, or rollback code without personally walking through the change, the spec it satisfies, the failure-mode analysis the AI produced, and the integration test that exercises the failure path — that week was a failure of review discipline, regardless of how much was shipped.

### The public-facing version

**AI writes the code. Humans do the reasoning. Every change that touches your production ships with a human-reviewed failure-mode analysis and a real-host integration test, and the founders personally validate every engine, capture, and rollback change before it merges.**

That sentence is marketable, defensible, and verifiable. It is the commitment customers are paying for when they buy trust.

### The goal

A team of 2 with AI leverage ships the feature velocity of a 10-engineer traditional team. The human attention that would have gone to the other 8 engineers' code gets invested where AI cannot help: customer calls, auditor meetings, conference talks, failure-mode investigation, FedRAMP paperwork review, and the personal reasoning about what makes a rollback handler safe at 3 AM in a customer environment we have not yet seen.

---

## What This Roadmap Is Not

Worth naming explicitly to prevent drift:

- **It is not a product roadmap.** Features will be driven by customer needs, not by this document. The feature roadmap lives separately.
- **It is not a revenue plan.** Revenue targets belong in the financial plan. This roadmap is about the moat-building activities that enable revenue, not the revenue itself.
- **It is not a hiring plan.** The team-of-2 assumption holds until month 6-9, at which point the first hire should be a federal sales/CS person per the strategy memo.
- **It is not flexible on FedRAMP timing.** Every other moat has some slack. FedRAMP does not. Starting late is starting behind forever, because calendar time is the one thing the process requires.

---

## The One-Paragraph Version

**Hanalyx's mission is to be the safety rail that every critical Linux change — human or AI — runs through before touching production. Over the next 18 months, with a team of 2 and heavy AI leverage, we will invest in seven compounding trust moats that AI cannot replicate: production track record, auditor relationships, FedRAMP authorization, community, liability absorption, canonical upstream status, and long-tail production experience. Each moat has a specific 18-month target, a monthly KPI, and quarterly investments. The sum of these investments is a structural lead that a well-funded AI-accelerated competitor cannot close by writing more code, because none of these moats are made of code. They are made of calendar time, human trust, and real production exposure — the three resources no amount of AI improvement can compress.**

---

*End of document.*
