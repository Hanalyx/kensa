# Will Hanalyx Become More or Less Valuable as AI Improves?

**Status:** Founder analysis
**Context:** The founder's question — "if I wake up tomorrow and AI is 10x better, does OpenWatch/Kensa become more or less valuable?"
**Short answer:** More valuable, if we lean into the parts of the business that compound with time and trust rather than code volume.

---

## Take the fear seriously

The naive version of the fear is correct: **if AI gets 10x better, the labor cost of writing a Kensa competitor drops by 10x.** Someone with a weekend and a good prompt can ask Claude or GPT-5 to generate 500 YAML rules mapping CIS RHEL 9 to remediation handlers. They can ask it to generate rollback logic for sshd config changes. They can ask it to build a FastAPI dashboard. Code volume stops being evidence of effort.

If our moat was "we wrote a lot of code," then yes — our moat gets smaller every month AI improves. That's a real concern and it shouldn't be waved away.

But the question worth sitting with is: **was code volume ever actually the moat?** And if it wasn't, what was, and does AI make that thing more or less valuable?

---

## What changes vs. what doesn't

Honest decomposition. For each thing that matters in this business: does AI 10x improvement make it *cheaper to produce* (erodes our position) or *more scarce in the market* (strengthens our position)?

### Things AI 10x improvement makes cheaper — and therefore erodes

- Writing YAML rules. AI can author 500 rules in an afternoon.
- Framework mapping (CIS → NIST → STIG cross-references). Pure text transformation. Trivial for AI.
- Documentation, READMEs, API specs. Trivial.
- The dashboard UI (OpenWatch frontend). AI can scaffold a React app in minutes.
- Customer support tier 1. AI handles it already.
- Boilerplate code generation. This is what AI is best at.

### Things AI 10x improvement does not touch — and therefore become more valuable because the code around them gets cheaper

- **Production trust.** "Will I let this tool modify my prod configs at 3 AM?" is a question that can only be answered with a track record, not a demo. AI generating a tool that claims to be rollback-safe doesn't make the customer trust it. The question "has this been tested under real failure conditions across real customer fleets?" is answered in calendar time, not compute time.
- **FedRAMP authorization.** This is an 18-month human-bound process involving 3PAOs, continuous monitoring documentation, agency sponsorship, and policy review. AI helps with the documentation load but doesn't compress the timeline. A startup that begins FedRAMP authorization today lands it 18 months from now. **AI does not speed this up.**
- **Liability absorption.** When Kensa rolls back a change and it fails and it breaks prod, someone has to be legally and insurably responsible for the outcome. That someone is a company with E&O insurance, contracts, and a phone number. AI companies do not assume this liability. The value of "we carry $10M in errors & omissions insurance and we will show up when it breaks" goes up in an AI-commoditized world, not down.
- **Auditor relationships.** The Big 4 talking to the vendor about how to interpret evidence. The ATO reviewer at a federal agency who has worked with our team before. These are human trust networks that compound over years.
- **The long tail of production failure modes.** AI is excellent at the 80% of cases that appear in training data. The 20% that actually breaks — the weird RHEL kernel version with a custom SELinux policy, the sshd drop-in file that conflicts with a non-standard PAM module, the package that has a different name on Oracle Linux — is where production automation lives or dies. That 20% is not in the training data because it's the stuff that was hard enough that nobody wrote a blog post about it. You only learn those cases by running in real customer environments and breaking things and fixing them. AI can't fabricate that experience.
- **Being the canonical upstream.** When AI makes forks cheap, "which version is the real one" becomes a harder question, not an easier one. The canonical project — the one with the blog, the maintainers, the auditor relationships, the reference deployments — becomes more valuable because there are now 50 AI-generated knockoffs and customers need a way to distinguish signal from noise.

### Things AI 10x improvement makes more valuable in an unexpected way

- **Community.** AI can fork code. AI cannot fork a community. The humans who hang out in GitHub Discussions, contribute rules, file issues, write integrations — that social graph is uniquely uncopyable. In a world where every company can instantly generate a Kensa-lookalike, the question customers ask shifts from "which tool is best?" to "which tool has a real community behind it that will still exist in 3 years?"
- **Opinionated defaults and judgment calls.** AI is great at doing what you tell it. AI is bad at knowing what not to do. "Which rules should we ship and which should we exclude because they break too often in the wild?" is a judgment call that comes from experience, not from training data. Kensa's 20% of manual / command_exec / grub rules that are honestly flagged as non-capturable is exactly the kind of judgment call AI won't make — AI will generate confident-sounding rollback code for all of them, and that confidence is worse than honesty.

---

## The Kensa/OpenWatch-specific answer

Apply that decomposition to the specific product and here's the picture:

**If the moat was "539 rules across 7 frameworks" — we are in trouble.** AI makes that replicable by anyone. But the earlier audits already established that the rules are not the moat. They were always the weakest part of the story.

**If the moat is the rollback-safe state engine — AI improvement makes it more valuable, not less.** Here's why. The engine's value isn't the *idea* of rollback-safe automation. AI can describe that idea, and it can even generate code that implements it at a superficial level. The value is: does it actually work when nginx fails to restart at 3 AM on a RHEL 9 box with a weird SELinux context and a non-default crypto policy? That question is answered by running in production for months and fixing the failure cases one by one. It is a moat made of **calendar time**, not code volume. AI does not give you calendar time.

And here's the second-order effect that actually matters: **as AI gets better, more and more production infrastructure will be modified by AI agents.** An AI coding agent running in CI that tweaks Linux configs. An AI SRE assistant that "helps" with production changes. An autonomous remediation agent that applies patches. Every one of these agents has the same problem: how do I know the change I just made didn't break prod, and how do I undo it if it did? The rollback-safe state engine is **exactly the primitive an AI agent needs to safely operate in production.** We are not competing with AI. We are building the safety rail that AI agents will eventually need to run against. In five years, the pitch is not "we help humans avoid breaking prod" — it's "we are the layer AI agents use to make changes without breaking prod." That market is larger than compliance, not smaller.

---

## The thing the fear is actually pointing at

The fear is slightly mis-aimed. The risk isn't "AI will replicate my code." The risk is **"AI will let a competitor with better distribution, better brand, or better capital catch up on capabilities I spent years building."**

That's a real risk. The mitigation is not to try to out-code AI — we can't, nobody can. The mitigation is to build the things AI doesn't touch:

1. **Start FedRAMP authorization now.** It's 18 months of human-bound process. A competitor who starts six months from now is always 6 months behind on the single biggest federal unlock. This is the most valuable thing we can do this year from an AI-defensibility standpoint.
2. **Get a track record in production as fast as possible.** One customer running Kensa for six months without breaking prod is worth more than a hundred AI-generated rollback handlers. The clock on trust starts ticking the day the first customer installs, and you can't rewind it.
3. **Own the category conversation.** The weekly blog posts about the rollback engine aren't marketing fluff — they're the establishment of a reference point. When someone in 2027 asks "where does the rollback-safe Linux automation category come from?" the answer needs to be Hanalyx. AI doesn't write the origin story of a category; people do.
4. **Invest in the community, not the code.** GitHub stars, Discussions activity, rule contributions, integrations people build on top of the project. These are the things that only exist if real humans chose to spend time with the project. They're the hardest thing for an AI-accelerated competitor to replicate, because the competitor can generate code but can't generate people's attention.
5. **Use AI aggressively ourselves.** The right response to "AI might make my competitors faster" is not "I'll hunker down and hope." It's "I'll use AI harder than they do." A team of 2 with Claude + Codex is already doing work that would take 6-8 traditional engineers. Keep pressing. The companies that lose to AI are not the ones whose moat gets commoditized; they're the ones who refused to use AI while their competitors did.

---

## The honest residual risk

One scenario genuinely concerns me:

**A well-capitalized AI-native security company (think $50M Series A, YC-backed, 10 engineers with strong AI leverage) decides to build a rollback-safe Linux automation product from scratch in 2026.** They can ship the engine faster than we did, because AI is better now than when we started. They out-market us because they have capital. They land design partners faster because they have investor networks. This is the thing that could beat us to the category.

The defense against this scenario is **time and trust**. Every month we have a customer running Kensa in production without incident is a month that competitor has to earn. Every rule we ship, every failure mode we fix, every auditor who sees our evidence format becomes muscle memory in the market that a newcomer has to displace. This is why the 90-day plan is urgent. Every month of delay is a month a hypothetical competitor could use to close the gap.

But here's the thing — that competitor exists with or without AI improving 10x. AI doesn't create that competitor; capital and talent do. And the defenses are the same: ship fast, get customers, build trust, own the category. These are the right moves whether AI improves 10x or 0x.

---

## The one-sentence answer

**If AI gets 10x better tomorrow, our code becomes less valuable and our track record, our auditor relationships, our FedRAMP authorization, our community, our liability insurance, our canonical upstream status, and our long-tail production experience all become more valuable — and the strategic move is to invest aggressively in the things AI doesn't touch, while using AI harder than anyone else to build the things AI does touch.**

Kensa and OpenWatch become **more valuable** in an AI-improving world, if we lean into the parts of the business that compound with time and trust rather than with code volume. The rollback engine is the best possible product for this world because it's precisely the primitive AI agents will need to operate safely in production. We are not building something AI will replace. We are building something AI will depend on.

What should keep a founder up at night is not "AI will replicate my code." It's **"am I moving fast enough to turn my current 6-month head start into a 24-month structural lead before a well-funded competitor catches up?"** That's the real clock, and it's a clock we can control.
