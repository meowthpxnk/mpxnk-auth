# My own python library tempolate

- [Template usage](#template-usage)
- [Template update](#template-update)
- [Workflow usage](#workflow-usage)
- [Customise changelog](#customise-changelog)
- [Support oldest versions](#support-oldest-versions)

## Template usage

1. Add new repository in PyPI
   Go to [https://pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing)
   Add new GitHub repository

- Project name - Your project name
- Owner - Your github username
- Repository - Repository name
- Workflow name - `publish.yaml`
- Environment name - `publish`

2. Clone repository on your pc

```sh
git clone https://github.com/meowthpxnk/PROJECT_NAME
```

3. Run renaming script

```sh
poetry run rename_lib
```

4. ❗️ALERT❗️Replace `LIB_DESCRIPTION` in pyproject.toml with your library description.
5. ❗️ALERT❗️Replace README.md with your package docs.
6. Create commit with message such as `feat!: Init project`. Push.
7. Go to github repository actions and run CI/CD workflow.

## Template update

1. Add template upstream

```sh
git remote add template-upstream https://github.com/meowthpxnk/mpxnk-lib-template
```

1. Fetch upstream and merge changes

```sh
git fetch template-upstream
git merge template-upstream/main --allow-unrelated-histories -m "chore: sync template"
```

## Workflow usage

Workflow has environment variables:

- run-lint - Run linting
- run-tests - Run pytests tests
- run-release - Create release version
- run-build - Build project into tmp folder
- publish-to-pypi - Finally publish to pypi

You can run some jobs if you need, only lint or only tests.

## Customise changelog

1. Run workflow with variables

- ✅ Lint
- ✅ Tests
- ✅ Release
- ✅ Build
- ❌ Publish

1. Pull repository

```sh
git pull
```

1. Change changelog custom
2. Commit changes
3. Run workflow with variables

- ✅ Lint
- ✅ Tests
- ❌ Release
- ✅ Build
- ✅ Publish

## Support oldest versions

1. Create branch from oldest version
   Example:

```sh
git checkout -b support/v0.1.x v0.1.5
```

1. Fix bug
2. Update branch

```sh
git add .
git commit -m "fix: Main fix 0.1.x"
git push origin support/v0.1.x
```

1. Add version for build in `pyproject.toml`

```toml
[tool.semantic_release.branches.support-v01]
match = "support/v0.1.x"
```

1. Use workflow with from your branch name `support/v0.1.x` and publish version
2. If u need to deploy this fix to main version merge branch and publish again from branch `main`

```sh
git checkout main
git merge support/v0.1.x
git push origin main
```

---

$XOXO$
_meowthpxnk_
..
