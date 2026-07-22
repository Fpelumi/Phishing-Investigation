# Technical Analysis

Five unsolicited emails received by a single Gmail account between 9 and 22 July 2026. One is a credential-harvesting attempt. Four are commercial bulk mail from two separate operations.

They are analysed together because the comparison produces conclusions that no single message supports.

---

## Contents

1. [The headline](#the-headline)
2. [Sample set](#sample-set)
3. [Sample 1: credential harvest](#sample-1-credential-harvest)
4. [Samples 2 to 4: the recruitment cluster](#samples-2-to-4-the-recruitment-cluster)
5. [Sample 5: contrast case](#sample-5-contrast-case)
6. [What the comparison shows](#what-the-comparison-shows)
7. [Recommendations](#recommendations)
8. [Method, confidence and limitations](#method-confidence-and-limitations)

---

## The headline

**Four of these five messages passed SPF, DKIM and DMARC in full.**

Only the outright credential-harvesting attempt failed authentication. The other four were delivered through Mailgun, SendGrid and Amazon SES, correctly signed and correctly aligned, and implemented one-click unsubscribe to the standard mailbox providers now require.

By every measure email security controls actually check, four of the five were indistinguishable from legitimate mail at the point of delivery.

This is not a failure of those controls. They are answering the question they were built to answer, which is *did the stated sender really send this*. They were never designed to answer *should this have been sent*. As DMARC enforcement has spread, the practical effect has been to push unwanted mail onto correctly-configured infrastructure rather than to reduce its volume. Senders who cannot authenticate get filtered. Senders who can, do not.

---

## Sample set

| Ref | Description | Received | Authentication | Delivered via |
|---|---|---|---|---|
| 1 | iCloud credential harvest | 9 Jul | SPF pass, DKIM permerror, **DMARC fail** | Rented VPS, OVH Canada |
| 2 | Recruitment, `jobadmiration` | 22 Jul | **All pass** | Mailgun |
| 3 | Recruitment, `careercougar` | 22 Jul | **All pass** | SendGrid |
| 4 | Recruitment, `jobadmiration` | 21 Jul | **All pass** | Mailgun |
| 5 | Rewards, list validation | 20 Jul | **All pass** | Amazon SES |

Samples 2 and 4 are conclusively the same operation. Sample 3 is probably the same operation. Sample 5 is unrelated to all of them.

---

## Sample 1: credential harvest

A message claiming the recipient's iCloud account was locked and their photos and videos would be deleted.

### Authentication

| Check | Result | What it means |
|---|---|---|
| SPF | pass | The sending host is authorised by the owner of the envelope-sender domain. That domain is attacker-controlled, so this authorises the attacker's own server. |
| DKIM | **permerror** | Not a signature mismatch. A signature was attached, but no public key exists in DNS at the declared selector. |
| DMARC | fail | SPF passed but did not align. |

**The SPF pass is the most misread element here.** SPF verifies only that the sending server was authorised by the domain it declared. Where the sender owns that domain, the check is trivially satisfied and carries no assurance whatsoever. A pass indicates a purpose-registered domain rather than a spoofed one.

**The DKIM result is worth reading carefully.** Gmail's summary view flattens `permerror (no key for signature)` into "FAIL". Those are different conditions: the key was never published, rather than the signature being invalid. Either the operator enabled signing without publishing the key, or the DNS record was published for the campaign and withdrawn. Both are consistent with short-lived infrastructure. The distinction is lost in the client summary, which is why the analysis works from raw source throughout.

**Why DMARC failed despite the SPF pass:**

| Role | Domain |
|---|---|
| Visible `From:` header | `5ibhni.nx8om7.dskpn2[.]us` |
| Envelope sender, which SPF checked | `live-jobscheduling-icloudamazffffonawsdd2277.waterints[.]com` |

DMARC needs a pass *and* alignment with the `From:` header. SPF passed for a `waterints[.]com` subdomain, which does not align. DKIM does declare an aligned domain but returned `permerror`, so it cannot supply alignment either. Both paths fail.

### Two of the four delivery hops are fabricated

`Received:` headers are added by each server that handles a message, so the chain reads bottom-up. Anything added before the message reached a server you trust could have been written by the sender.

**The trusted hop**, added by Google on receipt:

```
Received: from unbeatablecloud.us.com (unbeatablecloud.us.com. [51.161.21.203])
        by mx.google.com with ESMTPS ...
```

A single, direct submission from `51.161.21.203` to Google's MX. No relay.

**The fabricated hops**, which claim the message passed through Sailthru, a legitimate email service provider, including an instance apparently belonging to a well-known publisher:

```
Received: from njmta-53.sailthru.com (173.228.155.53) by dailybeast-a.sailthru.com ...
Received: from nj1-madbrick.flt (172.18.20.7) by njmta-53.sailthru.com ...
```

Four reasons this is false:

1. Both sit below the Google hop, inside the attacker-controlled portion of the message
2. Google recorded direct receipt from the OVH address. Had it come from Sailthru, Google would have received it from Sailthru
3. `172.18.20.7` is RFC 1918 private space and cannot route publicly
4. They cite a Sailthru envelope sender, but the authenticated envelope sender was the `waterints[.]com` address

The purpose is to borrow a reputable provider's standing, and to mislead any analyst who reads the chain without first working out which hops are trustworthy.

**No conclusion in this analysis relies on those two headers.**

### Five evasion techniques

**Unicode homoglyphs in the display name.** The sender renders visually as "Payment_Declined" but is not ASCII:

| Character | Codepoint | Block |
|---|---|---|
| `𝗣` | U+1D5E3 | Mathematical Alphanumeric Symbols |
| `𝗲` | U+1D5F2 | Mathematical Alphanumeric Symbols |

Any rule matching the literal string fails. Display-name rules must normalise Unicode first, or they are bypassed at zero cost.

**Structured as a bounce message.** The message declares `Content-Type: multipart/report; report-type=delivery-status`, meaning an automated delivery failure notice. The content is an HTML phishing page. Delivery status notifications often receive lighter filtering as system-generated mail.

**No Message-ID.** The header reads `...SMTPIN_ADDED_MISSING@mx.google.com`, Google's marker for a message that arrived without one, requiring Google to generate it. Legitimate mail systems set this reliably. Its absence indicates crude sending tooling.

**Bayesian poisoning.** The plaintext alternative contains an unrelated header line, a long numeric string, and roughly 180 characters of random consonants. Nobody using an HTML mail client ever sees it. Its function is to dilute the message's statistical profile against content classifiers.

**Payload on Google Cloud Storage.** The link points at `storage.googleapis[.]com`. That host cannot be blocked without unacceptable collateral impact, and a cautious user inspecting the link sees a recognisable Google domain. The actionable indicator is the bucket name, `vcxbiuouioui`, not the host.

### The redirect is invisible to scanners

```
hxxp://storage.googleapis[.]com/vcxbiuouioui/IMd02.html#/redirect.html?syv=<token>
```

Everything after the `#` is a URL fragment, and **fragments are never transmitted to the server**. They are processed only by the browser.

So a scanner fetching this URL receives a static HTML object and no indication of where it goes. The redirect runs in client-side JavaScript reading `location.hash`. Even the hosting provider's own logs contain no record of the destination.

The four extracted URLs differ only in a token carrying variant markers (`Out_`, `Uns_`) that distinguish the main call to action from the unsubscribe link. Decoding produced no readable output, so the token holds no plaintext address, but it may still map to the recipient in the sender's own records. It was not submitted to any public analysis service for that reason.

### Infrastructure

| Attribute | Value |
|---|---|
| Sending IP | `51.161.21.203` |
| ASN | AS16276, OVH SAS |
| ASN type | **Hosting** |
| Location | Beauharnois, Quebec |
| Reverse DNS | `unbeatablecloud.us[.]com` |
| Abuse contact | `abuse@ovh[.]ca` |

A rented virtual server, not an email service provider. Legitimate mail from a major consumer cloud service does not originate this way. OVH is a legitimate provider being abused; cheap, quickly-provisioned servers suit bulk operations because they are disposable.

**Four domains across four functions:**

| Layer | Domain | Registered domain |
|---|---|---|
| `From:` header | `5ibhni.nx8om7.dskpn2[.]us` | `dskpn2[.]us` |
| Envelope sender | `live-jobscheduling-icloudamaz…waterints[.]com` | `waterints[.]com` |
| Reverse DNS | `unbeatablecloud.us[.]com` | `us[.]com`, a second-level registry |
| Payload hosting | `storage.googleapis[.]com` | Legitimate, abused |

Both attacker sending domains use random or brand-imitating labels beneath the registered name, consistent with wildcard DNS. **Blocking a fully-qualified hostname here achieves nothing**, since a replacement costs the operator no money and no time. Blocks must be applied at the registered domain.

### One detail that corroborates

The subject line and `Date:` header both carry a `-0400` offset. Beauharnois observes UTC minus 4 in July, so the timestamp matches the sending server's own local time. Delivery at 10:52 BST equals 05:52 EDT.

That timestamp is genuine, which is notable in a message where two other headers are demonstrably forged.

---

## Samples 2 to 4: the recruitment cluster

Three job-advertisement emails, all presenting as `Luton`, arriving between 21 and 22 July.

### Everything authenticates

| | Sample 2 | Sample 3 | Sample 4 |
|---|---|---|---|
| Display name | `Luton` | `Luton` | `Luton` |
| Local part | `Listings@` | `Listings@` | `Listings@` |
| Domain | `jobadmiration[.]com` | `careercougar[.]com` | `jobadmiration[.]com` |
| Provider | Mailgun | SendGrid | Mailgun |
| SPF / DKIM / DMARC | pass / pass / pass | pass / pass / pass | pass / pass / pass |
| Received | 22 Jul, 12:24 | 22 Jul, 12:15 | 21 Jul, 12:17 |

There is no header forensics to do here. Nothing is spoofed and nothing is forged. The analysis has to move to identity, infrastructure and behaviour instead, which is the harder problem.

### Samples 2 and 4 are conclusively the same operation

Two headers are byte-identical across both.

**`X-Mailgun-Sid`**, which is base64. Decoded:

```
["45479","<RECIPIENT>","926016"]
```

A subscriber identifier, the recipient address, and a list identifier. **`45479` and `926016` are the same in both messages.** The recipient occupies the same slot on the same list in both sends.

The list number is independently corroborated by the envelope sender, which uses variable envelope return path addressing:

```
Return-Path: <bounce+12ef01.926016-<RECIPIENT>@jobadmiration[.]com>
                              ^^^^^^
```

**`X-Feedback-Id`**, also identical, including its 24-character hexadecimal account identifier.

This replaces inference with evidence. Shared display names and send windows are circumstantial. A shared subscriber record is not.

### The true origin is a Google Cloud VM

Both Mailgun samples record the hop *before* Mailgun:

```
Received: from mta2.jobadmiration.com (104.202.31.34.bc.googleusercontent.com ...)
```

`googleusercontent.com` is Google Cloud Platform's reverse DNS domain. The convention places octets in reverse, so this corresponds to roughly **`34.31.202.104`**.

```
[GCP virtual machine]
  running an MTA identifying as mta2.jobadmiration[.]com
        |
        v
[Mailgun relay]
        |
        v
[mx.google.com]
```

The operator runs their own mail server on Google Cloud and relays outbound through Mailgun. This matters because the Mailgun address is drawn from a shared pool and identifies nobody, whereas the GCP instance is operator-controlled, identical across both samples, and a valid target for a Google Cloud abuse report.

The hostname `mta2` implies at least one sibling not represented in this sample set.

### The operation dates to 2023

The account identifier in `X-Feedback-Id` follows the structure of a MongoDB ObjectId, in which the leading four bytes encode a Unix timestamp:

```
0x653bd604  =  1698420228  =  27 October 2023, 15:23:48 UTC
```

If that reading is right, the associated record predates these messages by **two years and nine months**.

That is inconsistent with a disposable operation. Burner accounts are created shortly before use and abandoned on suspension. An identifier of this age indicates a sender that has maintained a provider relationship, and therefore an acceptable complaint rate, over an extended period. It raises the assessed sophistication considerably, and it appears nowhere except in that one header.

### Behaviour is more durable than infrastructure

**Message-ID construction.** Samples 2 and 4 share an identical form:

```
<20260722112419.2f611cd47387e944@jobadmiration[.]com>
 |__ 14-digit UTC __| |__ 16 hex __|
```

This is emitted by the sending application, not typed per message, which makes it a stronger correlation signal than any address. Decoding the timestamps and converting to local time reproduces the recorded receipt times exactly, so the value is reliable for timeline work.

**Send window.** All three arrived between 12:15 and 12:24 local, across two consecutive days. That is a scheduled job.

Both of these sit high on the Pyramid of Pain. Changing a domain costs a registration fee. Changing an established send schedule disrupts the operator's own delivery and engagement patterns, which is a real cost they are unlikely to accept.

### What is not evidence

Two observations could be misread and are recorded here as explicitly not indicative.

**Different sending IPs at the same provider.** Samples 2 and 4 came from `69.72.42.2` and `143.55.232.14`. Both belong to Mailgun. Email service providers assign outbound addresses from shared pools as routine operation and the sender has no control over which is used. This is not evasion.

**Delivery latency.** One second for two samples, 58 seconds for the third. Queue latency at a shared provider varies with load and is not attributable to the sender.

Recording non-findings matters. An assessment that treats routine infrastructure behaviour as adversary tradecraft overstates its case, and a reviewer who spots one such error will reasonably discount the findings that are sound.

### Sample 3 is probably, not certainly, the same operation

It shares the display name, the local part and the send window, but it runs through SendGrid on a separate domain with SendGrid's own Message-ID format, so none of the Mailgun identifiers are available for comparison. **No shared identifier links it to the other two.**

The correlation remains circumstantial. It is recorded as such rather than folded into the conclusive finding.

### Subject lines escalate

| Order | Subject | Construction |
|---|---|---|
| 1 | `We're Hiring` | Generic |
| 2 | `Immediate Start, <NAME>` | Forename, urgency |
| 3 | `New Message: <NAME>: Applicants Requested` | Forename, platform-notification framing, implied pending action |

The third is built to look like an automated alert from a job site the recipient already uses, exploiting an assumed existing relationship rather than advertising anything.

The list holds the recipient's forename as well as the address, which indicates a richer data source than a scraped address list.

---

## Sample 5: contrast case

A separate operation, analysed to test whether the characteristics above are specific to the recruitment cluster or general to unsolicited mail.

| Attribute | Value |
|---|---|
| Display name | `Flash Rewards` |
| Sender | `hello@flashrewardsmail[.]co[.]uk` |
| Provider | Amazon SES, `eu-west-2`, London region |
| SPF / DKIM / DMARC | pass / pass / pass |
| Subject | `Second Notice, Email Confirmation Needed` |

### Not part of the cluster

| | Recruitment cluster | Sample 5 |
|---|---|---|
| Send window | 12:15 to 12:24 | 14:50 |
| Local part | `Listings@` | `hello@` |
| Domain naming | Employment word pairs | Brand plus `mail` plus `.co.uk` |
| Provider | Mailgun, SendGrid | Amazon SES |
| Registry | gTLD | Nominet |

No shared characteristics beyond full authentication and delivery through a mainstream provider.

### Jurisdiction changes what can be done

The `.co.uk` registration and London-region sending infrastructure place this sender within UK jurisdiction, unlike the `.com` domains elsewhere in the set. That opens routes the other samples do not have:

- The Privacy and Electronic Communications Regulations apply to unsolicited direct marketing to individual subscribers
- UK GDPR obligations attach to the processing of the recipient's personal data
- The Information Commissioner's Office is the competent regulator and provides a public reporting route
- Nominet operates a registrant validation process, giving a second escalation path independent of the hosting provider

Worth stating plainly: **technical indicators determine what can be blocked, but registry and jurisdiction determine what can be escalated, and the two do not correlate.** This is the only sample in the set with a meaningful regulatory remedy, and it is not the most technically suspicious one.

### The pretext is list validation, not theft

"Second Notice" asserts a prior communication. Where none was sent, it manufactures both an existing relationship and an overdue task, and it works because verifying the claim takes more effort than complying with it. "Email Confirmation Needed" then frames the requested action as administrative rather than commercial.

The likely objective is not a click for its own sake but **confirmation that the address is live and monitored**, which materially increases its value for resale or for targeting with higher-value campaigns.

If that reading is right, the harm is to the recipient's data position rather than their credentials or their money, and it is realised later and elsewhere. That has a direct consequence for impact assessment: the absence of a credential-capture page does not mean the absence of harm.

This is inferred from subject construction alone. Body content and link destination remain unexamined.

---

## What the comparison shows

### Everyone hides behind infrastructure that cannot be blocked

| Sample | Relies upon | Why it survives |
|---|---|---|
| 1 | Google Cloud Storage for the payload | Shared with legitimate services at enormous scale |
| 1 | OVH for sending | Large legitimate host; only the specific address is actionable |
| 2, 4 | Google Cloud compute, relaying via Mailgun | Both unblockable at the provider level |
| 3 | SendGrid | Major transactional provider |
| 5 | Amazon SES | Major transactional provider |

Sample 1 is the instructive case because it does both at once. Its sending infrastructure was disposable and its authentication failed, yet the payload sat in Google Cloud Storage precisely because that host cannot be blocked. The operator understood which parts of the chain could be sacrificed and which had to survive.

**Consequence.** Controls keyed on sender reputation, sending domain, hosting provider or authentication result are ineffective against four of these five. What remains is content analysis, sender behaviour over time, domain registration age, and user reporting.

### The most durable indicators are not addresses

| Indicator | Example | Cost to change |
|---|---|---|
| Sending hostname | `5ibhni.nx8om7.dskpn2[.]us` | None. Wildcard DNS. |
| Sending IP | `69.72.42.2` | None. Provider pool. |
| Registered domain | `dskpn2[.]us` | Registration fee plus DNS and auth setup |
| GCS bucket | `vcxbiuouioui` | Low, but links must be reissued |
| Message-ID construction | `<ts.hex@domain>` | Requires changing sending software |
| Send schedule | Daily, 12:15 to 12:24 | Disrupts the operator's own delivery patterns |

The two most durable things recovered are a sending-application fingerprint and an operational routine. **Neither is visible in a single message.** Both emerged only from comparison, which is the practical case for campaign-level analysis over per-message triage.

### The recipient's address is buried in the headers, once deliberately

| Sample | Header | Encoding |
|---|---|---|
| 2, 4 | `Return-Path`, `X-Feedback-Id` | Plaintext, VERP form |
| 2, 4 | `X-Mailgun-Sid` | Base64 |
| 3 | `Return-Path` | Plaintext, VERP form |
| 5 | `X-Mailer-Info` | **Base64 of the reversed string** |

VERP addressing and base64 tracking identifiers are standard bulk mail practice and carry no adverse implication. Reversing a string before encoding it serves no functional purpose. It defeats tooling that decodes base64 and searches the result, which is the ordinary way encoded identifiers are found. The most plausible explanation is deliberate concealment.

**This has a direct handling consequence.** Removing the visible address from a sample is not enough. Two of these four retained a fully recoverable copy after every plaintext occurrence was replaced, and one was hidden by reversal.

Sanitisation was therefore performed by decoding every base64 candidate string in both forward and reversed orientation, substituting inside the decoded value, and re-encoding in the original form. Verification used the same method rather than a text search, because **a text search reports these files as clean whether or not encoded copies remain.**

During that work the verification script flagged an earlier draft of this analysis, which had quoted the obfuscated string while explaining it. A redacted sample can be undone by the document describing it. The string is withheld here for that reason.

---

## Recommendations

### Detection

1. **Normalise display names to Unicode before string matching.** Sample 1 defeated exact matching at no cost using Mathematical Alphanumeric Symbols.
2. **Treat structural anomalies as signals independent of authentication.** Absent `Message-ID`, `multipart/report` declared on non-bounce content, and plaintext parts containing no readable text are all detectable regardless of whether DMARC passes.
3. **Correlate on Message-ID construction and send window**, not on sending address alone. These survive the infrastructure rotation that defeats address-based lists.
4. **Where a URL points at shared cloud storage, evaluate the path.** The host carries no signal; the bucket does.

### Blocking

5. **Block at the registered domain, never the hostname.** Wildcard DNS makes hostname blocks worthless.
6. **Do not block ESP or hosting provider ranges.** Collateral impact is disproportionate and the operator is not tied to any specific address.

### Escalation

7. **Report to the ESP where one is identified**, citing the account identifiers rather than the message. Account suspension is the only control that reaches the operator directly.
8. **Report operator-controlled cloud instances to the cloud provider.** The GCP host behind the recruitment cluster is a better abuse target than the Mailgun relay.
9. **Use the ICO route where the sender is within UK jurisdiction**, in addition to technical blocking.

### Organisational

10. **Awareness training must address correctly-authenticated unwanted mail.** Guidance framed around spotting spoofed senders does not address four of these five samples.
11. **Treat "confirm your email address" as its own category.** The objective may be validation of the address rather than credential capture, and the harm is realised later and elsewhere.

---

## Method, confidence and limitations

### Method

| Stage | Approach |
|---|---|
| Acquisition | Exported as `.eml` with full headers. Recipient identifiers removed before commit. |
| Header analysis | Raw source throughout. Client summary views checked but not relied upon. |
| Delivery path | First trusted hop established, everything below it treated as attacker-supplied. |
| Infrastructure | Open-source lookup of authenticated sending addresses: ASN, type, geolocation, reverse DNS, abuse contact. |
| Correlation | Comparison of tracking headers, Message-ID construction and send timing across samples. |
| Indicators | Extracted, defanged, annotated with confidence, durability and blocking guidance. |
| URLs | Not retrieved. Live analysis deferred to an isolated environment. |

### Two decisions worth stating

**Trusted versus untrusted evidence.** Any `Received:` header added before a message reaches infrastructure under independent control may have been written by the sender. Sample 1 contains four and two are fabricated. Identifying the first trustworthy hop and discarding everything below it is what made the delivery path recoverable at all.

**Raw source over client summaries.** The mail client reported sample 1's DKIM result as a plain failure. The raw header records `permerror`, which has different implications. Summary interfaces are lossy, and here the difference mattered.

### Inferences, identified as such

Two findings rest on reasoning rather than confirmed fact:

- The reversed-octet reading of the Google Cloud reverse DNS record, giving `34.31.202.104`. Confirm by forward lookup before operational use.
- The interpretation of the `X-Feedback-Id` value as a MongoDB ObjectId, from which the October 2023 date derives. The structure is consistent with an ObjectId but this is not confirmed.

### Limitations

Five samples received by one individual over two weeks. Not a representative sample of mail in general, and no claim is made about prevalence.

The credential-harvesting landing page was not retrieved, so no assessment is offered of what it requested or how credentials were handled. Body content and link destinations for samples 2 to 5 remain unexamined.

Attribution extends to hosting infrastructure only. No claim is made about any operator's identity.

**No conclusion is offered as to whether any sender in this set is operating unlawfully.** The findings establish that the messages were unsolicited, that specific technical characteristics were present, and that samples 2 and 4 share an origin. Nothing further.
