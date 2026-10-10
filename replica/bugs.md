# Bugs

Only what was reproduced. Each was found by a failing test written first, then fixed; the tests stay.
Nothing is committed, so there is no commit id yet. Branch: `feat/nexora-link`.

| id | sev | where | steps | expected | actual | evidence | status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B0 | S3 | `login()` and `login_sso()` (existing code, 1.1.0) | sign in, read `users.last_login` | updated | never saved (confirmed on the untouched HEAD code: `None` after a login; now set): the user was detached from the session before the pending update was flushed. It also would have dropped a newly linked SSO identity | `test_an_existing_email_is_linked_once` failed | fixed (flush before expunge) |
| B1 | S4 | SSO subject | token with a 65 character `sub` | refused | truncated to 64, so two long ids with a shared prefix would become one account | `test_an_overlong_subject_is_refused_not_truncated` | fixed |
| B2 | S3 | JIT first sign-in | two tabs complete the first SSO sign-in together | one succeeds, the other is refused | unique-constraint error surfaced as a 500 | `test_a_concurrent_first_sign_in_is_a_clean_refusal_not_a_500` | fixed |
| B3 | S3 | SSO email | token with a 260 character email | refused | would fail on insert (PostgreSQL `varchar(254)`) as a 500 | `test_an_overlong_email_is_refused_not_a_server_error` | fixed |
| B4 | S4 | webhook channel name | create a channel named three spaces | refused | created with an empty name after trimming | `test_a_blank_name_is_refused` | fixed |

## Not bugs (checked)

- Numeric, hex, octal and short spellings of 127.0.0.1, `localhost.` and `0` as webhook hosts: all refused with the real resolver.
- A body-validation error (422) is returned before the permission check on a route with a body and no auth: existing behaviour, not changed; no data is exposed.

## To check (not reproduced)

- Real Clerk JWTs: whether the JWT template can emit `email_verified` as a boolean (JIT refuses otherwise).
- `pip-audit` locally (the tool could not build its environment here); CI runs it.
- PostgreSQL migration run (CI job).
- Console keyboard access to clickable table rows and focus trapping in dialogs (known gaps listed in `design/components.md`).

## Open S1 or S2: none.
