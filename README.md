[README (1).md](https://github.com/user-attachments/files/30282477/README.1.md)# Phishing and Unsolicited Mail Analysis

Analysis of five unsolicited emails received over a two-week period in July 2026, comprising one credential-harvesting attempt and four commercial bulk messages forming two separate operations.

Covers header forensics, delivery path reconstruction, evasion technique identification, infrastructure attribution, campaign correlation and indicator extraction.

## Principal finding

**Four of the five samples passed SPF, DKIM and DMARC in full and were delivered through mainstream email service providers.** Only the outright credential-harvesting attempt failed authentication.

The controls most organisations rely on would have flagged one message in five. Authentication answers whether the stated sender actually sent the message. It does not answer whether the message should have been sent, and adoption of DMARC enforcement has moved unwanted mail onto correctly-configured infrastructure rather than reducing it.

## Report sections

| Section | Contents |
|---|---|
| [`report/03-technical-analysis.md`](report/03-technical-analysis.md) | Credential-harvesting sample: authentication failure, forged delivery path, five evasion techniques |
| [`report/04-campaign-analysis.md`](report/04-campaign-analysis.md) | Correlation of the recruitment cluster; contrast sample and jurisdictional analysis |
| [`report/05-cross-case-findings.md`](report/05-cross-case-findings.md) | Cross-sample conclusions, indicator durability, recommendations |
| [`report/06-raw-header-analysis.md`](report/06-raw-header-analysis.md) | Findings recoverable only from raw sources: true origin, conclusive correlation, operational age |
| [`iocs/iocs.csv`](iocs/iocs.csv) | Indicators with confidence, durability and blocking guidance |
| [`evidence/`](evidence/) | Sanitised samples and redaction methodology |

## Summary of findings

### Sample 1: credential harvest

Claimed a locked iCloud account and threatened deletion of stored photos and videos. Established as a credential-harvesting attempt sent from rented hosting infrastructure.

| # | Finding | Significance |
|---|---|---|
| 1 | **SPF passed, DMARC failed** | The SPF pass authorises the attacker's own domain. DMARC failed on alignment because the envelope sender and the visible `From` domain differ. |
| 2 | **Two `Received:` headers are fabricated** | Both claim transit through Sailthru, a legitimate email service provider. One cites RFC 1918 private address space, which cannot route publicly. |
| 3 | **Unicode homoglyphs in the display name** | Characters from the Mathematical Alphanumeric Symbols block render as "Payment_Declined" but defeat byte-level string matching. |
| 4 | **Message structured as a bounce notification** | Declared `Content-Type: multipart/report; report-type=delivery-status` while carrying an HTML phishing page. |
| 5 | **Payload hosted in Google Cloud Storage** | The host domain is legitimate and cannot be blocked. The bucket name is the actionable indicator. |
| 6 | **Redirect target held in the URL fragment** | Fragments are never sent to the server, so server-side URL scanners cannot observe the destination. |

### Samples 2 to 5: commercial bulk mail

| # | Finding | Significance |
|---|---|---|
| 7 | **Full authentication across all four** | SPF, DKIM and DMARC pass with correct alignment. Not spoofed, and not evading controls. |
| 8 | **True origin is an operator-run MTA on Google Cloud** | The recruitment cluster relays through Mailgun from its own GCP instance. The ESP address identifies nothing; the GCP host is operator infrastructure. |
| 9 | **Two samples conclusively linked by tracking headers** | Identical `X-Mailgun-Sid` subscriber and list identifiers establish the same account and the same list, replacing circumstantial correlation with direct evidence. |
| 10 | **Operation dates to October 2023** | An account identifier structured as a MongoDB ObjectId embeds a creation timestamp, indicating a provider relationship sustained for nearly three years. |
| 11 | **Recipient address encoded in headers, one instance obfuscated** | Present in plaintext, VERP, base64 and base64-of-reversed-string form. The last defeats ordinary encoded-PII detection. |
| 12 | **RFC 8058 one-click unsubscribe implemented throughout** | These senders meet bulk-sender requirements in order to be delivered, rather than evading them. |

### Detection consequence

Reputation-based and authentication-based controls are ineffective against four of these five samples. The two most durable indicators recovered are not addresses at all: a Message-ID construction reflecting the sending application, and a daily send window reflecting operational routine. Neither is visible in a single message. Both emerged only from comparison, which is the practical argument for campaign-level analysis over per-message triage.


---

## Method

| Stage | Approach |
|---|---|
| Acquisition | Exported as `.eml` with full headers preserved. Recipient address redacted before commit. |
| Header analysis | Raw source only. Client summary views were checked but not relied upon. |
| Delivery path | Established the first trusted hop, then treated everything below it as attacker-supplied. |
| Infrastructure | Open-source lookup of the authenticated sending IP: ASN, type, geolocation, reverse DNS, abuse contact. |
| Indicators | Extracted, defanged, and annotated with confidence and blocking guidance. |
| URL analysis | Deferred pending an isolated environment. Not retrieved from a working host. |

### Analytical approach

Two decisions shaped the analysis and are worth stating explicitly.

**Trusted versus untrusted evidence.** `Received:` headers are added by each handling server, so any header present before the message reached infrastructure under independent control could have been written by the sender. This message contains four such headers and two are fabricated. Establishing which hop was the first trustworthy one, and discarding everything below it, was the step that made the delivery path recoverable. No conclusion in the report rests on attacker-supplied data.

**Raw source over client summaries.** The mail client reported the DKIM result as a plain failure. The raw header records `permerror (no key for signature)`, which is a different condition with different implications: the key was never published, rather than the signature being invalid. Summary interfaces are lossy, and the difference mattered here.

---

## Repository structure

```
report/
  03-technical-analysis.md    Credential-harvesting sample
  04-campaign-analysis.md     Campaign correlation and contrast case
  05-cross-case-findings.md   Cross-sample conclusions
  06-raw-header-analysis.md   Raw source findings
  phishing-report.md          Template, remaining narrative sections
  README.md                   Section status index
iocs/
  iocs.csv                    Indicators with durability ratings
evidence/
  README.md                   Redaction methodology
  sample-sanitised.eml        Credential harvest
  sample-A..D-*-sanitised.eml Bulk mail samples
```

---

## Handling and safety

- **All indicators are defanged.** URLs use `hxxp`, domains use `[.]` notation. Nothing in this repository is clickable.
- **No live retrieval.** The phishing URL was not visited from an uncontrolled environment.
- **Evidence is preserved as received.** The only modification to `sample-sanitised.eml` is redaction of the recipient address. Nothing else was altered, including the attacker's own formatting.
- **No third-party personal data.** The sample was received by the author. No other individual's information appears.
- **Token handling.** URLs in the sample carry per-recipient tokens. These were not submitted to public analysis services, as public submissions are searchable and could disclose recipient identity.

---

## Status

| Section | State |
|---|---|
| Technical analysis, sample 1 | Complete |
| Campaign analysis, samples 2 to 5 | Complete |
| Cross-case findings | Complete |
| Raw header analysis | Complete |
| Indicators | Complete |
| Initial email overview | Outstanding |
| Impact assessment | Outstanding |
| Recommendations | Outstanding |
| Executive summary | Outstanding |
| Live URL analysis | Outstanding, requires isolated environment |

---

## Limitations

Five samples received by a single individual over a two-week period. Not a representative sample of mail in general, and no claim is made about prevalence.

The credential-harvesting landing page was not retrieved, so no assessment is offered of what it requested or how credentials were handled. Attribution extends to hosting infrastructure only, and no claim is made about any operator's identity. No conclusion is offered as to whether any sender is operating unlawfully, only that the messages were unsolicited and that specific technical characteristics were observed.

Two findings rest on stated inferences rather than confirmed fact: the reversed-octet reading of the Google Cloud reverse DNS record, and the interpretation of the account identifier as a MongoDB ObjectId. Both are identified as such at the point they are made.
