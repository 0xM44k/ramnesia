# Security & responsible use

## Authorized use only
RAMnesia is a defensive **memory-forensics** tool. Only analyse memory you are
authorised to: your own hosts and lab, or systems you have explicit written
permission to examine (an engagement, an incident you're responding to). Do not
use it to extract data from systems or accounts you do not own or control.

Recovered material often contains secrets (API keys, tokens) and private
conversation content. Handle output as sensitive: the tool redacts secrets and
withholds secret context from HTML reports by default, but JSON output and the
analyst console are complete — store and share them accordingly.

## Reporting a vulnerability
If you find a security issue in RAMnesia itself, please **do not** open a public
issue. Email the maintainer (see `pyproject.toml`) with:
- a description and impact,
- steps or a proof of concept,
- affected version.

You'll get an acknowledgement within a few days and a fix or mitigation plan.
Coordinated disclosure is appreciated.

## Supported versions
The latest minor release receives fixes. RAMnesia is pre-1.0; APIs may change
between minor versions (see `CHANGELOG.md`).
