# Contributing to mcpinspect

Thank you for your interest in contributing to `mcpinspect`! 

The most valuable contribution you can make is adding new checks to catch emerging MCP threat vectors.

## Adding a New Check

1. **Create the Check File**
   Depending on what you are checking, create a new file in `mcpinspect/checks/description/yourcheck.py`, `mcpinspect/checks/response/yourcheck.py`, or `mcpinspect/auditor/checks/yourcheck.py`.

2. **Implement the Check ABC**
   Your class must inherit from `Check` and set the `id` (the next sequential `MCI-DXX`, `MCI-RXX`, `MCI-XXX`, or `ACI-XX` number), `title`, and `severity`.

   ```python
   from mcpinspect.checks.base import Check, CheckResult, Severity
   from mcpinspect.protocol.models import ServerManifest

   class YourNewCheck(Check):
       id = "MCI-D99"
       title = "Detects your new pattern"
       severity = Severity.HIGH

       def run(self, manifest: ServerManifest, ...) -> list[CheckResult]:
           results = []
           # Your logic here
           if found_issue:
               results.append(self._fail(
                   finding="Found the issue.",
                   evidence="the specific bad string",
                   location="tool:name:description"
               ))
           
           return results if results else [self._pass()]
   ```

3. **Register the Check**
   Add your new check to the `ALL_CHECKS` list in `mcpinspect/checks/__init__.py` or `mcpinspect/auditor/checks/__init__.py`.

4. **Add Fixture Data**
   Modify the appropriate fixture in `tests/fixtures/` to serve data that triggers your new check.

5. **Write Unit Tests**
   Add tests in the corresponding test file (e.g., `tests/test_description_checks.py`). Ensure you test:
   *   `test_clean_passes()`: Ensure non-malicious data passes.
   *   `test_pattern_triggers()`: Ensure your specific pattern correctly triggers the check.
   *   `test_evidence_captured()`: Validate that `result.evidence` accurately extracts the malicious string.

6. **Submit your Pull Request**
   Your PR must include:
   - The check implementation.
   - The tests.
   - An entry in the `README.md` checks table for your new rule.

### Running Tests Locally

Ensure you have `poetry` installed, then run:

```bash
poetry install
poetry run ruff check .
poetry run mypy --strict mcpinspect
poetry run pytest --cov=mcpinspect --cov-fail-under=80
```
