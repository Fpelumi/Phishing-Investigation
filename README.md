[README.md](https://github.com/user-attachments/files/30282241/README.md)
# Evidence

## Samples

| File | Sample | Received |
|---|---|---|
| `sample-sanitised.eml` | iCloud credential harvest | 9 Jul 2026 |
| `sample-A-jobadmiration-sanitised.eml` | Recruitment, "We're Hiring" | 22 Jul 2026 |
| `sample-B-careercougar-sanitised.eml` | Recruitment, "Immediate Start" | 22 Jul 2026 |
| `sample-C-jobadmiration-sanitised.eml` | Recruitment, "Applicants Requested" | 21 Jul 2026 |
| `sample-D-flashrewards-sanitised.eml` | Rewards, list validation | 20 Jul 2026 |

## Redaction method

The recipient address and name were removed. **This required more than text replacement.**

The address was present in these samples in four distinct forms:

| Form | Location |
|---|---|
| Plaintext | `To`, `Delivered-To`, message body |
| VERP envelope | `Return-Path`, `X-Feedback-Id` |
| Base64 | `X-Mailgun-Sid` |
| Base64 of the reversed string | `X-Mailer-Info` |

Redaction was therefore performed by decoding every base64 candidate string in both forward and reversed orientation, substituting within the decoded value, and re-encoding in the original form.

Verification used the same method rather than a text search. A text search reports these files as clean whether or not encoded copies remain, so it cannot be relied upon.

See `report/06-raw-header-analysis.md` section 6.4.

## What was not modified

Nothing beyond the recipient's address and name. Sender data, infrastructure identifiers, tracking tokens, timestamps, formatting and the attacker's own text are preserved as received.

Tracking identifiers belonging to the sender (`X-Mailgun-Sid` subscriber and list numbers, `X-Feedback-Id` account identifier) are retained deliberately. They are the evidence on which the correlation findings rest.

## Unmodified originals

Not committed. Held offline.
