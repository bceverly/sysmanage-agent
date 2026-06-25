# Contributing to SysManage Agent

Thank you for considering contributing to the Agent! Your help strengthens our cross-platform management capabilities and international reach.

---

## Licensing & Contributor Agreement

SysManage Agent is distributed under AGPLv3. By contributing, you agree:
- Your contributions will be licensed under AGPLv3.
- They may be incorporated into the proprietary Enterprise Edition.
- You retain your rights while granting redistribution under AGPLv3.

---

## How to Contribute

### 1. Open an Issue
Got a bug or idea? Report it clearly:
- What’s happening? What should happen?
- Attach logs or reproduction steps if available.

Use `bug` or `enhancement` labels.

### 2. Start Development
Fork the repo, then:
```bash
git checkout -b feature/your-change
```

After cloning, run **`make install-dev`** to install Python
dependencies AND activate the in-repo git hooks (see
`.githooks/README.md`).  The `pre-push` hook runs `make lint`
before allowing pushes; this catches the same things CI catches
without burning a cycle to find out.  Skip the hook in genuine
emergencies with `git push --no-verify`.

### 3. Key Development Guidelines
- Use `bandit` for security linting:
  ```bash
  bandit -r .
  ```
- Python linting with `black` + `pylint`:
  ```bash
  black .
  python -m pylint .
  ```

### 4. Testing
Write tests under `tests/`. Running all tests:
```bash
make test
```

### 5. Submit PR
- Polished commit message.
- Explain what you changed and why.
- Mention i18n if you impacted user-facing text or logs.

---

## Internationalization Contributions

The Agent supports 14 languages. To contribute:
- Set correct translations in `i18n/`.
- Update translation files for affected languages.
- Indicate language additions or updates in PR.

`make lint` runs an **offline** i18n completeness gate (`translate-check`,
no translation service required) alongside `i18n-validate`, so an
untranslated string fails locally at `pre-push` rather than in CI. Fill
gaps with your local model rig — `make translate SERVICE=http://<host>:8765`
— then re-run `make lint`.

---

## Project Standards

- **Security-First**: No hardcoded secrets; use cryptography best practices.
- **Permissions**: Maintain file and directory hardening.
- **CI/CD**: Keep pipelines passing and adhere to test coverage.

---

## Code of Conduct

We follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/).

---

## Tips for Contributors

- Discuss large enhancements via issue first.
- Keep your PR small and focused.
- Let’s make SysManage Agent stronger together—thank you for your support!

