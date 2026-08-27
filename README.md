# CheckMyLink UK

A free, non-profit tool that helps UK residents check whether a link, phone
number, or message they've been sent might be a scam or phishing attempt.
Paste a link, get a plain-English verdict: **Safe**, **Caution**, or
**Danger**.

CheckMyLink UK is built for everyone, including people who are not
comfortable with technology or who may be targeted by scammers. There's no
jargon, no account, no login, and no cost.

## Why this exists

Scam and phishing links sent by text, email, or WhatsApp are one of the most
common ways people in the UK are defrauded - fake delivery texts, fake bank
alerts, fake HMRC refunds, and more. CheckMyLink UK gives anyone a quick,
free second opinion before they click.

This project supports the spirit of the UK's **Take Five to Stop Fraud**
campaign - *Stop, Challenge, Protect* - by making it easier to pause and
check before acting. **CheckMyLink UK is an independent community project
and is not officially affiliated with Take Five, Action Fraud, or any bank
or government body.**

If you believe you've been scammed, always report it for free to
[Action Fraud](https://www.actionfraud.police.uk), the UK's national fraud
reporting service.

## How it works

Every link submitted is checked against several free, no-API-key-required
sources, combined into one weighted score and a simple verdict:

- **URLhaus** (abuse.ch) - public list of known malware-hosting URLs
- **OpenPhish** community feed - public list of confirmed phishing URLs
- **Spamhaus DBL** - free DNS-based domain blocklist
- **Domain age** (WHOIS) - very recently registered domains are riskier
- **Typosquatting detector** - local Levenshtein-distance comparison against
  major UK brands commonly impersonated in scams (Barclays, HSBC, Lloyds,
  NatWest, Santander UK, Royal Mail, HMRC, DVLA, TV Licensing, DPD, Evri)
- **SSL certificate check** - flags very new certificates on domains that
  look like brand impersonation

If any single source fails or times out, the scan degrades gracefully
("unable to check X") rather than crashing - no result ever depends on every
source being reachable.

**No accounts, no login, and no record is kept of what anyone searches.**
The homepage shows only two anonymous running totals (links checked,
dangerous links caught) with no link back to any individual search.

## Running locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open http://127.0.0.1:8000 in a browser.

## Running the tests

```bash
pytest
```

## License

MIT - see [LICENSE](LICENSE).
