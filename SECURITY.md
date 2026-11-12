# What erpguard does NOT protect against
- A malicious *user*, compromised model weights, or side channels (out of scope).
- Misleading the user with false text: it gates privileged *actions*, not what the model says.
- Attacks that put the payload in a field a declassifier accepts (e.g. a directory entry the attacker can edit).
- Free-text arguments are the weakest spot: hybrid mode falls back to session-level taint, which costs CONFIRM prompts.
- Partial-overlap matching (16-char windows) can attribute text to a trusted source if it overlaps the user's message; joins take the *lowest* integrity across all matches, which limits but does not eliminate this.
- The bundled evaluation uses a deterministic "gullible" simulator and a mock ERP. Re-run with a real LLM before drawing conclusions.
Report issues privately to the maintainers.
