"""Public builds (Track S): the prompts are stripped out, and this marker stands in their place.

The export (`scripts/public/export.py` in the private repo) rewrites every AGENT.md as its front matter plus
this line, and PREAMBLE.md as this line alone. The code treats it as "no instructions": the deterministic
checks run as usual, and any Claude call is refused (`NoInstructions`).
"""

STRIPPED_MARKER = "<!-- handscheck: instructions for Claude are not part of this build -->"
