# i18n workflow

coauth's user-facing strings live in [Project Fluent][fluent] files
under `translations/` (`en.ftl`, `zh.ftl`, …). We do **not** sync with
any SaaS localisation platform (no Localazy, Crowdin, Transifex,
etc.). All translation work happens directly in this repository against
the source `.ftl` files.

## Why no SaaS sync

- **Sovereignty.** A coauth deployment can be self-hosted by a circle
  with no external dependencies; the translation pipeline matches.
- **Reviewability.** Every translation lands as a PR, gets the same
  diff review and CODEOWNERS attention as any code change, and is
  reproducible from the git history.
- **Simplicity.** The fluent files are small (low-hundreds of strings,
  not thousands) and the diff churn is manageable without external
  tooling.

## Editing translations

Maintainers and translators edit `translations/<locale>.ftl` directly:

```ftl
# en.ftl
login-button = Sign in
login-button.title = Sign in to your account

# zh.ftl
login-button = 登录
login-button.title = 登录您的账户
```

When adding a new string:

1. Add the key to `translations/en.ftl` first (English is the source
   of truth for keys).
2. Add a placeholder or translated value to every other locale file —
   missing keys in non-English locales fall back to the English value
   at runtime but the lint check (below) flags them so they are not
   forgotten.
3. Include the rendered string in your PR description so reviewers can
   sanity-check the wording without launching the UI.

## Crowdsourcing translations

For new locales or significant content additions from non-maintainer
contributors:

- Open a GitHub PR against `translations/<locale>.ftl`. Squash-merge,
  not rebase, so the historical attribution stays on the squash
  commit.
- The `i18n` CODEOWNERS entry routes the PR to the maintainer group
  responsible for that locale. New locales should not land without at
  least one maintainer who can sign off on terminology choices going
  forward.
- For larger translation drives we accept multiple small PRs (one per
  page / module) rather than one mega-PR — reviewers can keep up and
  conflicts stay manageable.

## mdbook / documentation sync

The user-facing docs under `docs/<locale>/` are also maintained by
hand. There is no machine translation step:

- The English book under `docs/en/` is the source of truth for
  structure. When you add or rename a chapter in `docs/en/SUMMARY.md`,
  mirror the change in `docs/zh/SUMMARY.md` (and any other locale
  books) in the same PR.
- Translated chapters live alongside the English ones with the same
  filename, e.g. `docs/zh/development/i18n-workflow.md` for this file's
  Chinese counterpart.
- The lint check in CI flags chapters that exist in English but are
  missing in `zh` (or vice versa) so structural drift surfaces in PR
  review rather than at release time.

For untranslated chapters, prefer leaving the English file
un-mirrored and adding a `TODO(i18n)` comment in
`docs/<locale>/SUMMARY.md` over shipping a stub Chinese page that just
re-renders the English text — readers can tell when something is
untranslated vs deliberately written in English, and the lint check
treats `TODO(i18n)` as an acknowledged gap rather than a regression.

[fluent]: https://projectfluent.org/
