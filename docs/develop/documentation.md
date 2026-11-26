# Documentation and GitHub Pages

Zensical reads `zensical.toml` and the Markdown files under `docs/`. See the
navigation list in `zensical.toml` when adding or moving a page. Use relative
Markdown links between pages so they work in both local previews and the GitHub
Pages project site.

## Preview and check locally

```sh
mise install
mise run workspace:docs:dev
mise run workspace:docs:build
```

The dev task serves the site on `127.0.0.1:8000`. The build task uses strict
link validation and generates the static site in `site/`.

## Publish changes

PR CI builds the docs. A push to `master` runs the
[Pages deployment workflow](https://github.com/jamestrousdale/quickunlocker/actions/workflows/deploy-docs.yaml).
It builds and uploads the generated site, then deploys that artifact to the
`github-pages` environment. In the repository's **Settings → Pages**, select
**GitHub Actions** as the publishing source before the first deployment. See the
[GitHub Pages publishing guide](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

The site URL is
[https://jamestrousdale.github.io/quickunlocker/](https://jamestrousdale.github.io/quickunlocker/).
To diagnose a failure, open the deploy workflow run and check its build and
deploy jobs separately.
