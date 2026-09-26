# Coverage notes

## Reproducing CI's branch list quickly: filtered path coverage

CI measures coverage over the whole unit suite, which takes long enough (about an hour
under Xdebug) that closing a coverage gap by re-running it is not workable. The shortcut:
run path coverage against only the test classes that exercise the code in question.

```bash
XDEBUG_MODE=coverage vendor/bin/phpunit --testsuite unit --filter '<TestClass>|<OtherTestClass>' --path-coverage --coverage-text
```

Filtered this way it finishes in seconds and reports the same branch list CI does for
those classes, because branch coverage of a class depends only on the tests that reach it.
Widen the filter if a class is also reached from another suite's tests (the queue driver
tests reach `TWebhookModule`, for instance) so the numbers match what CI will see.

This is a local diagnostic run only. `AGENTS.md` still holds for anything committed: the
options in `phpunit.xml` and the composer scripts are the project's, CI runs `composer
coverage` unchanged, and `--filter` remains the one option to add when running the suite
as part of the check. `--path-coverage` needs Xdebug (or PCOV does not support it), so set
`XDEBUG_MODE=coverage` for the run.
