# Hanalyx 18-Month Strategy Memo

**Status:** Draft v1
**Context:** CEO-level strategic direction for OpenWatch + Kensa
**Audience:** Founders, advisors, future hires
**Based on:** Full-codebase audit of `/home/rracine/hanalyx/{openwatch,kensa,kensa-go,website}`. Python kensa was an internal-only prototype with no production users; it is being phased out, and kensa-go is the production engine going forward.

---

## Founding Context (the constraints that shape everything)

- **Team size:** 2 founders
- **Force multiplier:** Heavy AI/agent leverage (Claude, OpenAI Codex). Effective engineering throughput is closer to 4-5 traditional engineers on code-generation tasks — but customer development, sales, support, and brand work remain human-bound.
- **Customers:** Zero paying customers today. Complete strategic freedom, but also zero revenue and zero reference accounts.
- **Network:** Federal contracting experience and relationships. This is the single most valuable non-code asset the company has.
- **License posture:** Already set correctly. Kensa under BSL 1.1 → Apache 2029. OpenWatch under AGPLv3 + Managed Service Exception. This is the MongoDB/Grafana playbook and it is the right configuration for the strategy below. Do not change it.

**What these constraints mean in plain English:** You cannot run two products in parallel. You can run one product with two surfaces (federal + an open-source brand play), as long as the second surface is engineering-only and does not require a separate go-to-market motion. Revenue has to come from federal in the first 12 months, or the company runs out of runway before the long-term moat has a chance to form.

---

## The Strategic Answer

**Single track: become the default closed-loop compliance automation tool for federal Linux infrastructure. One product, one pitch, one buyer for the first 12 months.** Use the federal network to land 3-5 lighthouse customers on a sharpened pitch ("we replace SRE remediation labor, not just scan"). Use AI leverage to ship the product velocity of a much larger team.

**In parallel, with zero incremental GTM cost, position the rollback-safe Linux state engine as a standalone open-source category.** Not as a SaaS product. As a *category definition* via content, public rule corpus, and engineering-led marketing. This costs one blog post a week and one GitHub README. It plants a flag for the commercial SaaS wedge that becomes a real product at month 15+, *after* federal revenue is stable.

This is a **one-track go-to-market with a two-track codebase story**. The federal customer pays the bills. The open-source posture builds the flywheel. The commercial SaaS wedge is a month-15 decision, not a month-0 decision.

---

## The Component That Could Stand Alone as a Moat

You asked which component of OpenWatch or Kensa could, by itself, be a valuable tool or a moat. After the full audit, the clearest answer:

### The rollback-safe Linux state engine (kensa-go's transactional handler set + capture/rollback discipline)

Everything else in the stack is replicable in 3-6 months by a funded competitor. The rollback engine is not. Here is why:

1. **Nobody else has it.** Tenable, Wiz, Qualys, Lacework, Rapid7, Prisma — every one of them is a "tell you what's wrong" tool. Ansible has no native rollback. Chef/Puppet have partial idempotence but no capture-before-change semantics. SaltStack has no rollback. **Closed-loop remediation with automatic rollback on failure is a category of one.**

2. **The reason nobody else has it is not technical — it's organizational.** Building rollback-safe production mutation is *terrifying*. The failure mode is "we broke prod at 3 AM." Enterprise security vendors' legal teams will not let them build it. You've already absorbed that risk: kensa-go ships 19 capturable handlers covering the bulk of the 539-rule corpus, with the four-phase transaction discipline (capture → apply → validate → commit-or-rollback) gating every mutation. **Your scariness is your defensibility.**

3. **It is useful far beyond compliance.** kensa-go's transactional handler model captures pre-state across packages, configs, services, kernel parameters, SELinux booleans, mount options, cron jobs, PAM modules, and more — independent of any compliance framework. The four-phase transaction reverses each applied step using the captured state. The compliance rules are just one set of inputs. This engine is a generic **"safer Ansible"** primitive. Any SRE team that has ever broken prod with an automation run is a potential buyer.

4. **Open-sourcing it aggressively is the right move.** The federal sale requires auditability of the code that modifies production. The commercial pitch requires trust in the blast-radius-reduction story. Both require the code to be readable. You're already BSL 1.1 — that's correct. The missing piece is **positioning**, not licensing.

**What this means for strategy:** The rollback engine is the *real* product. Kensa (compliance rules) is one application layered on top. OpenWatch (dashboard) is one UI on top of that. If you think of it this way, the federal business is the first application of a more general platform, and the category you're creating is "rollback-safe Linux automation" — not "compliance scanning."

This framing is what makes the two-track-codebase-one-track-GTM play work. You ship federal features, but the *engineering narrative* is about the rollback engine. Content, talks, blog posts, open-source contributions, README — all point at the engine as a category. When month 15 arrives and you're ready to launch a commercial SaaS wedge, the category has already been named and the open-source project is already the reference implementation.

---

## The 18-Month Plan (revised for team of 2 + AI leverage)

**Engineering note (added 2026-05-07):** All engineering deliverables in this plan run against kensa-go (the Go rewrite of Kensa). Python kensa was the internal prototype that established the rule corpus and CLI patterns; it has no production users and is being phased out. Several deliverables below were already shipped in kensa-go ahead of schedule: OSCAL evidence export (`internal/evidence/oscal.go`), Ubuntu/Debian probe support and `apt_present`/`apt_absent` handlers, the versioned API boundary (kensa-go's frozen-v1 `api/` package), the parity scaffold, and the `kensa-fuzz` failure-injection harness. See `docs/KENSA_API_DOC.md` and `docs/roadmap/` for current state and forward-looking plans (kernel-ABI migration, CLI GNU/POSIX migration).

### Months 0–3: Sharpen the pitch, land first customers, plant the category flag

**Human-bound work (the two founders):**
- Rewrite the Hanalyx homepage around the closed-loop pitch. Kill "508 rules across 7 frameworks" as the hero. Replace with verbs: "Scan. Remediate. Roll back. Prove it to your auditor." Promote the Kensa page's *"Evidence Auditors Actually Trust"* line to the home headline.
- Soften the fedgov-exclusionary framing slightly without abandoning it. SDVOSB stays in the footer. "Federal Linux Infrastructure" in the hero narrows the market unnecessarily — reframe as "Linux compliance for regulated enterprises, trusted by federal contractors." Leaves the door open for healthcare, fintech, utilities without abandoning federal.
- **Build the labor-replacement ROI calculator.** Inputs: host count, frameworks, current compliance FTE count. Outputs: hours saved, dollars saved, payback period. This is the single most powerful sales artifact possible in this category and **competitors literally cannot tell this story without admitting they don't do remediation.** Ship it this month as a public tool on the website.
- **Warm-introductions from the federal network.** Goal: 5 conversations by end of month 1, 3 lighthouse customers by end of month 3. These do not have to be paying deals. They have to be "yes, we will install Kensa on 50 hosts and give you a testimonial if it works." That is enough to unlock the next stage.

**AI-leveraged engineering work:**
- Ship **CIS Docker + CIS Kubernetes Node hardening rules** in Kensa. ~150 rules. With AI leverage this is ~3-4 weeks, not the 6-8 weeks a traditional team would need. This is the single biggest "we can't even consider you" objection-killer for any modern customer.
- Ship **Ubuntu LTS coverage** for the top 20 CIS/STIG rules. Not full parity yet — just enough to answer "does it work on Ubuntu?" with "yes, for the critical controls." AI leverage makes this tractable in 2-3 weeks. **[partially shipped 2026-04: kensa-go ships Ubuntu/Debian probes (`apt`, `dpkg`, `apt_unattended_upgrades`, `apparmor`, `ufw`, `ubuntu_advantage`) and `apt_present`/`apt_absent` capturable handlers; the top-20 rule subset still depends on rule-corpus authoring]**
- Ship **Slack + Jira integration** in OpenWatch. Both currently absent. Both are table stakes for enterprise. AI leverage: ~1-2 weeks each.
- **Begin the federal authorization track** for OpenWatch. FedRAMP Moderate is an 18-month process. Month 0 is the right start date so it lands at month 18 — exactly when federal sales need the unlock.

**Category flag-planting (no GTM cost):**
- Publish one engineering blog post per week about the rollback engine. Not about compliance. About production safety. About the pre-state capture mechanism. About how `_capture.py` works. About why automation rollback is hard. **Content that SREs and platform engineers read, not content that CISOs read.** This is the seed of the category.
- Rewrite the Kensa GitHub README to foreground the rollback engine. Put compliance second. Put "this is the only open-source tool that can apply a configuration change, validate it, and roll it back automatically if validation fails" in the first paragraph.

### Months 3–6: Convert lighthouses to revenue, deepen the federal wedge

**Human-bound work:**
- Convert 2-3 of the lighthouse customers to paid contracts. The federal deal size is $50K-$500K annual, paid up front, 3-year terms. Even one closed deal at $100K ARR means the runway extends materially.
- Begin direct outreach beyond the warm network. Target: federal contractors with 500-5000 RHEL hosts, STIG obligations, and an overworked platform team. The LinkedIn search is not difficult.
- First conference / talk submission. Not RSA or Black Hat. Something small and focused: a USENIX LISA, a SCaLE, a FOSDEM devroom. The talk is about the rollback engine, not about compliance. **This is how the category gets named in public.**

**AI-leveraged engineering work:**
- Ship **OSCAL evidence export and signed evidence bundles.** ~3-4 weeks with AI leverage. This is the structural moat play — when federal auditors start expecting Kensa-format evidence, your customers can't switch without their auditor's permission. This is the closest thing to external gravity available in this market. **[OSCAL export shipped in kensa-go via `internal/evidence/oscal.go`; signed evidence bundles pending the Ed25519 signer (M7 task #12) — envelopes today carry the canonical schema with empty signature bytes]**
- Ship **SAML/OIDC SSO** in OpenWatch. Currently absent. Required for any enterprise federal deal. AI leverage: ~1-2 weeks.
- **Refactor the Kensa ↔ OpenWatch integration** from direct library import to a versioned API boundary. Currently pinned as `kensa @ git+...@v1.2.5` with the Evidence dataclass as an implicit schema contract. This refactor unlocks both the eventual SaaS split and the community contribution story. AI leverage makes this ~4-5 weeks of focused work. **[shipped in kensa-go: the rewrite delivered the versioned API boundary directly via the frozen-v1 `api/` package (`docs/KENSA_API_DOC.md`); OpenWatch imports `kensa-go/api` rather than the Python library]**
- Continue weekly blog cadence on the rollback engine category.

### Months 6–12: Federal scale + FedRAMP authorization milestone

**Human-bound work:**
- Target: $200K-500K ARR from federal customers. 5-10 paying accounts.
- First external hire: a federal sales / customer success person. Not an engineer. The team of 2 is currently the bottleneck on the GTM side, not the engineering side. AI leverage is not helping with deal cycles, auditor conversations, and customer onboarding. **This hire is more valuable than an engineer at this stage.**
- Begin publishing a **public rollback engine changelog** that reads like a product blog. Every new capture handler, every new rollback type, every new mechanism. SREs subscribe to these. Over 12 months this builds a tiny but valuable audience of exactly the buyers who will matter in phase 4.

**AI-leveraged engineering work:**
- **FedRAMP Moderate authorization work** dominates this phase. Controls implementation, documentation, 3PAO interaction. AI leverage helps with the documentation load (which is enormous) but not with the human/process load.
- Ship **RHEL 10 rule coverage** ahead of competitors. Ubuntu LTS expansion to full CIS parity.
- Ship **continuous monitoring** features in OpenWatch that feed into the federal ConMon requirement. This is a federal-specific feature but it doubles as drift detection for commercial buyers later.
- Begin the **Kensa ↔ OpenWatch API split** in earnest. Goal: by month 12, the integration is clean enough that a commercial SaaS variant is a packaging decision, not a refactor.

### Months 12–18: The commercial wedge decision point

**Human-bound work:**
- Month 15: **strategic decision point.** Based on federal revenue trajectory and the audience that has formed around the rollback engine category, decide whether to:
  - **(A)** Launch a commercial SaaS wedge (DriftWatch / Statelock-style) as a separate brand at a separate domain. This requires hiring: 1-2 commercial-facing people and accepting a divided focus for 12 months.
  - **(B)** Stay pure federal, reinvest SaaS budget into federal sales capacity, target $2M+ ARR by month 24.
  - **(C)** Pursue acquisition interest from an existing compliance vendor who lacks the rollback engine. Valuation is much higher with a differentiated moat than without one.
- The honest default is **(B)** unless two things are true at month 15: (1) federal ARR is ≥ $500K and growing, AND (2) the rollback engine blog/open-source work has produced at least 1,000 GitHub stars and 5-10 inbound "can we pay for a hosted version?" conversations. Those two signals together are a genuine green light for the wedge. Absent them, SaaS is a distraction.

**AI-leveraged engineering work:**
- FedRAMP Moderate authorization **lands** at month 18. Use as the centerpiece of the first federal sales push.
- Rule velocity: ship STIG V2R8, V2R9 within 30 days of release. CIS updates within 60 days. This is a treadmill, but AI leverage makes it tractable for a team of 2.
- Begin offering a **hosted control plane upgrade** to existing federal customers — their scanner stays on-prem, their dashboard moves to a Hanalyx-hosted SaaS. Opt-in. This is the lowest-risk way to start collecting cross-customer telemetry (with explicit consent) while still serving federal.

---

## The First 90 Days: Concrete Actions

Because team-of-2 + zero customers means the first 90 days either work or the company is in trouble, here is an explicit punch list:

### Week 1
- [ ] Rewrite Hanalyx homepage hero. Ship the new closed-loop framing.
- [ ] Rewrite Kensa GitHub README to foreground the rollback engine.
- [ ] Draft the first customer outreach email to the federal network. Goal: 5 warm conversations booked by end of week 2.
- [ ] Decide the founder split: which founder owns GTM, which owns engineering. Do not split these 50/50. One person must own each.

### Weeks 2–4
- [ ] Ship the ROI calculator as a public web tool.
- [ ] Publish first two blog posts about the rollback engine category.
- [ ] First 5 federal conversations. Do not sell software. Listen. Find out what they're using today, what breaks, who does remediation.
- [ ] Begin CIS Docker rule authoring in Kensa (AI-accelerated).

### Weeks 5–8
- [ ] Two lighthouse customer installs. Free, in exchange for feedback and a testimonial. 50 hosts each is enough.
- [ ] Ship CIS Docker rules alpha. Ship Ubuntu LTS critical-rule subset.
- [ ] Third and fourth blog posts.
- [ ] First conference talk submission.
- [ ] Begin FedRAMP authorization process — even just the initial readiness assessment is enough to start the clock.

### Weeks 9–12
- [ ] Convert at least one lighthouse customer to a signed paid contract. Any size. Revenue matters less than the reference.
- [ ] Ship Slack + Jira integration.
- [ ] Fifth through eighth blog posts. By end of Q1 there should be a small audience forming around the rollback engine content.
- [ ] Begin second batch of federal outreach. By now the ROI calculator and blog content are ammunition for a colder outreach motion.

**If at the end of 90 days**: zero paid customers AND zero active lighthouse installs AND no measurable audience signal → the problem is positioning or market, not execution. Stop and rethink. Do not keep shipping features.

**If at the end of 90 days**: 1+ lighthouse customer actively using the product AND at least 1 paid contract in late-stage negotiation → the strategy is working. Continue.

---

## What to Say No To

- **Parallel SaaS wedge before month 15.** Tempting but fatal for team of 2 with no customers. The SaaS wedge becomes real when federal revenue is funding it.
- **AWS Security Hub / Azure Defender / GCP SCC integrations.** These make you a feed into a larger competitor's hub. Do not commoditize yourself.
- **SOC 2 Type 2 before month 12.** Required for commercial SaaS. Not required for federal. Defer.
- **CI/CD scanning integrations** (GitHub Actions, GitLab CI). Trivy/Grype/Snyk own this segment. Different buyer, different motion, no synergy.
- **More compliance frameworks** beyond what already exists. You're already at 7 frameworks with 95%+ STIG coverage. Adding HIPAA or SOX mappings has diminishing returns until there are customers asking for them.
- **Custom professional services engagements** beyond the first 2-3 lighthouse deployments. Services revenue is tempting when cash is short, but it scales linearly with headcount and distracts from the product. Say yes to paid pilots; say no to custom consulting.
- **Conference sponsorships, paid ads, outbound SDR tools.** All of these cost money you don't have and none of them work for a team of 2 selling into federal. Every dollar of marketing should go to content and product, not paid channels.
- **Hiring an engineer as the first hire.** AI leverage means the engineering bottleneck is not the tightest constraint right now. The GTM bottleneck is. First hire should be a federal sales / customer success person.
- **Refactoring, rewrites, or code cleanup that isn't on the customer path.** The codebase is good enough. Ship features customers will pay for.

---

## What This Strategy Gives Up

Worth naming explicitly, because every strategy has opportunity cost:

1. **The big commercial SaaS story.** Not abandoned — deferred to month 15+. If the federal track succeeds faster than expected, this gets pulled forward. If it doesn't, the SaaS wedge is a luxury that has to wait.
2. **Broad cloud-native positioning.** You will not compete with Wiz on cloud posture management. That is the right call.
3. **Non-Linux coverage.** Windows, macOS, containers-as-targets (vs containers-as-hosts) are all deferred. This narrows the market but focuses the product.
4. **The cross-customer benchmark signal flywheel.** This can only be built through multi-tenant SaaS. It's the deepest possible moat in this category and the current plan defers it for 15 months. **The risk:** if a well-funded competitor launches a commercial SaaS wedge with cross-customer signal in the next 12 months, they build the flywheel you gave up. The mitigation is that none of the current competitors have the rollback engine, so even if they build the flywheel they can't build the category-of-one story. The bet is that the rollback engine is a deeper moat than the signal flywheel.

---

## The One-Paragraph Version

Hanalyx has built a generic rollback-safe Linux state engine, packaged it as a federal compliance tool, and is selling it with positioning that under-leverages the moat. With a team of 2, no customers, heavy AI leverage, and a federal network, the correct 18-month play is: **one product, one pitch, one buyer — federal Linux compliance — on a sharpened positioning that leads with "we replace SRE remediation labor, not just scan"**. In parallel, with zero GTM cost, **plant the flag for a new category — "rollback-safe Linux automation" — through open-source posture and engineering-led content** so that when federal revenue stabilizes around month 15, a commercial SaaS wedge can launch into a category the market already recognizes. The federal customer pays the bills. The engineering narrative builds the flywheel. The commercial SaaS is a month-15 decision, not a month-0 decision. First 90 days: rewrite the homepage, ship the ROI calculator, land 3 lighthouse customers from the warm network, publish weekly content on the rollback engine. If those four things work, the strategy is working.

---

## Open Questions for the Founders

1. **Which founder owns GTM and which owns engineering?** This split must be clear before week 1. Do not 50/50 both.
2. **What is the actual runway in months?** The plan assumes at least 12 months of cash. If it is less, the 90-day checkpoint becomes a 60-day checkpoint and the plan compresses aggressively toward revenue.
3. **Is there appetite to take a small seed round in months 6-9?** A $500K-$1.5M round at the point of "3 lighthouse customers, 1-2 paid, ROI calculator live, rollback engine content picking up" is a very different raise than a pre-everything round. The answer shapes the pace of the federal sales push.
4. **Who is the first hire, and when?** My recommendation is a federal sales / customer success person around month 6, not an engineer. Worth validating against your own instincts and network.

---

*End of memo.*
