# 6. Raw Header Analysis

Findings available only from the raw message sources. The mail client authentication summaries used in sections 4 and 5 did not expose any of the following.

---

## 6.1 True origin of the recruitment cluster

Both `jobadmiration[.]com` samples carry a `Received:` header recording the hop **before** Mailgun:

```
Received: from mta2.jobadmiration.com (104.202.31.34.bc.googleusercontent.com ...)
```

`googleusercontent.com` is the reverse DNS domain for Google Cloud Platform compute instances. The convention places the octets in reverse order, so the PTR record shown corresponds to **`34.31.202.104`**, an address within Google Cloud's allocation.

**Delivery chain reconstructed:**

```
[GCP virtual machine, 34.31.202.104]
   running an MTA identifying as mta2.jobadmiration[.]com
                |
                v
[Mailgun, 69.72.42.2 / 143.55.232.14]
                |
                v
[mx.google.com]
```

**Assessment.** The operator runs their own mail transfer agent on a Google Cloud VM and relays outbound mail through Mailgun. Mailgun is the visible sender to any receiving system; the GCP instance is the actual origin and the point at which the campaign is generated.

This is materially more useful than the Mailgun address. The ESP address is drawn from a shared pool and identifies nothing. The GCP instance is operator-controlled infrastructure, is the same across both samples, and is a valid target for an abuse report to Google Cloud.

The hostname `mta2` implies at least one sibling, suggesting further sending capacity not represented in this sample set.

> Verification note: the reversed-octet interpretation of the PTR should be confirmed by forward lookup before the address is used operationally.

---

## 6.2 Conclusive link between samples A and C

Two headers are byte-identical across both `jobadmiration[.]com` samples.

### X-Mailgun-Sid

The value is base64. Decoded:

```
["45479","<RECIPIENT>","926016"]
```

Three fields: a subscriber identifier, the recipient address, and a list identifier.

**`45479` and `926016` are identical in both messages.** The recipient occupies the same subscriber slot on the same list in both sends.

The list identifier is independently corroborated by the envelope sender, which uses variable envelope return path addressing:

```
Return-Path: <bounce+12ef01.926016-<RECIPIENT>@jobadmiration[.]com>
                              ^^^^^^
```

### X-Feedback-Id

```
info-<RECIPIENT>@jobadmiration[.]com::653bd604a62321c3289bc8aa:mailgun
```

Identical in both messages, including the 24-character hexadecimal identifier.

**Assessment.** Section 4 established common origin on circumstantial grounds: shared display name, shared local part, shared Message-ID construction, consistent send window. These headers replace inference with direct evidence. Both messages were sent from the same Mailgun account, drawing on the same subscriber list, to the same list entry.

**Confidence: conclusive** for samples A and C.

---

## 6.3 Operational age

The identifier `653bd604a62321c3289bc8aa` follows the structure of a MongoDB ObjectId, in which the leading four bytes encode a Unix timestamp.

```
0x653bd604 = 1698420228 = 27 October 2023, 15:23:48 UTC
```

If the identifier is an ObjectId, the associated record was created approximately **two years and nine months before these messages were sent**.

**Assessment.** This is inconsistent with a disposable operation. Burner sending accounts are created shortly before use and abandoned once suspended. An identifier of this age indicates a sustained commercial operation that has maintained a provider relationship, and therefore an acceptable abuse-complaint rate, over an extended period.

The finding raises the assessed sophistication of this operator considerably, and it is not visible anywhere except in this header.

> Confidence: moderate. The inference rests on the identifier being an ObjectId, which is consistent with its structure but not confirmed. If correct, the timestamp is reliable.

---

## 6.4 Recipient address encoded in message headers

The recipient's address appears in each sample in multiple encodings.

| Sample | Header | Encoding | Recoverable |
|---|---|---|---|
| A, C | `Return-Path` | Plaintext, VERP form | Directly |
| A, C | `X-Feedback-Id` | Plaintext, VERP form | Directly |
| A, C | `X-Mailgun-Sid` | Base64 | On decode |
| B | `Return-Path` | Plaintext, VERP form | Directly |
| D | `X-Mailer-Info` | **Base64 of the reversed string** | Only after reversal and decode |

Sample D is the significant case. The address is reversed before base64 encoding:

```
Header segment:  <32-character base64 string, redacted>
Step 1, reverse the string
Step 2, base64 decode
Result:          moc.liamg@<local part reversed>
Step 3, reverse again
Result:          <RECIPIENT>@gmail.com
```

The header segment itself is withheld here, because reproducing it would reinstate a recoverable copy of the address in this document. That point is not incidental: a redacted sample can be undone by an analysis file that quotes the encoded value while explaining it.

**Assessment.** VERP addressing and base64 tracking identifiers are standard bulk mail practice and carry no adverse implication. Reversing a string before encoding it serves no functional purpose. It defeats detection by tooling that decodes base64 and searches the result, which is the ordinary method for locating encoded identifiers. The most plausible explanation is deliberate obfuscation.

### Consequence for evidence handling

**Redacting the visible address from a message is insufficient.** Two of these four samples retained a fully recoverable copy of the recipient address after the plaintext occurrences were replaced, and one of those was concealed by reversal.

Sanitisation for these samples was therefore performed by decoding every base64 candidate string in both forward and reversed orientation, substituting within the decoded value, and re-encoding in the original form. Verification was performed by the same method rather than by text search.

This is recorded because the failure mode is silent. A text search of the redacted files returns no match while a recoverable copy remains present.

---

## 6.5 Bulk sender compliance

All four samples carry:

```
List-Unsubscribe: <https://...>, <mailto:...>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```

This is one-click unsubscribe as specified in RFC 8058, offering both an HTTP and a mailto route.

**Assessment.** Major mailbox providers have required one-click unsubscribe from bulk senders since early 2024. Its presence indicates senders operating to meet those requirements rather than evading them, which is consistent with the full authentication observed across all four samples.

**Interpretation.** This does not establish that the senders are legitimate. It establishes that they are operating as commercial bulk mailers and have implemented what is necessary to maintain deliverability. The compliance is a deliverability measure, not evidence of good faith.

> The unsubscribe links carry per-recipient tokens. They were not exercised. Interaction confirms the address is live and monitored, which for a sender whose objective may be list validation is the outcome sought.

---

## 6.6 Additional observations

**Mailgun region.** Sending hosts `v52.v51e342bd.use4.send.mailgun.net` and `v514.v5f06b487.use4.send.mailgun.net` indicate the US East 4 region, despite UK-targeted content.

**SendGrid dedicated subdomain.** Sample B returns to `em9697.careercougar[.]com`, following SendGrid's dedicated sending subdomain convention. This requires the operator to have delegated DNS to SendGrid, which is a deliberate configuration step rather than a default.

**Malformed Reply-To in sample B.**

```
Reply-To: "careercougar.com" <careercougar.com@careercougar.com>
```

The local part is the domain name. This is consistent with a template field populated with the domain where a mailbox name was expected. It suggests automated tenant provisioning rather than manual configuration, and by implication a platform operating multiple sending domains.

**Divergent Reply-To addresses.** Samples A and C send from `Listings@` but direct replies to `info@`. Sample D sends from `hello@` and directs replies to `reply@`. Separation of sending and receiving addresses is normal for bulk mail and is noted only for completeness.

---

## Revised assessment

| Question | Position after section 4 | Position after raw header analysis |
|---|---|---|
| Are A and C the same operation? | Probable, on circumstantial grounds | **Conclusive.** Same account, same list, same subscriber record. |
| Is B part of the cluster? | Possible | Unchanged. No shared identifier found. Correlation remains circumstantial. |
| Where does the cluster originate? | Unknown, ESP only | **GCP instance `34.31.202.104`**, relaying through Mailgun. |
| How mature is the operation? | Unknown | Provider record dating to **October 2023**, if the ObjectId inference holds. |
| Are the senders evading controls? | Assumed | **No.** All four implement authentication and RFC 8058 unsubscribe. They comply in order to be delivered. |

The last row is the most important revision. The working assumption that unsolicited mail evades controls does not hold for this sample set. These senders satisfy every technical requirement mailbox providers impose, and are delivered on that basis. The controls are functioning as designed and are answering a question that does not determine whether the mail should have been sent.
