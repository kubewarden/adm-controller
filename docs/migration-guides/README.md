# Admission Controller's Migration Guide Process

*Adapted from [Avian's migration guide process](https://github.com/avianphysics/avian/tree/release-v0.6.0/migration-guides)*

A PR you made contained breaking changes?

When we make breaking changes to adm-controller, we need to communicate them to
users (Kubernetes Operators, Policy Authors, Policy Users, Integrators), so
they can update to the new version. To do this, when needed, we ship a
migration guide. To not need to remember nor re-review changelog, we ask PR
authors and reviewers to add to the draft migration guide for the `main`
branch. This will helps if reverting PRs.

## Where to put your migration changes

Add them to `docs/migration-guides/latest-to-main.md` draft, where `x` is the latest
released version number.
This draft will be promoted to `y-to-x.md` (`y` is previous version, `x` is
latest) when we release `x`.

## What to put

Migration guides should reflect the complete experience of migrating from the
last Helm chart stack to the next one:

- what breaking change has been made since the last release?
- why did we do the breaking change?
- how can users migrate?

The draft `latest-to-main.md` *does not need to be polished*. We will do an
editing pass on release.
Use terse, technical language (e.g: ASD-STE100), and include terms that users
might search for.

### Grouping changes

Each migration should be given its own section and clear name. If there are
*multiple* breaking changes layered on top each other, edit the existing guide
approach rather than writing a new section. 

### Style guide

- Short and sweet: what, then why, then how to migrate.
- Mention "before, we had behavior A. Now, we have behavior B".
- Make sure it's searchable by mentioning terms, types, and functions.
- If needed to reference versions of crates, policy SDKs, or APIs, reference the published version.
- Provide values.yaml or code examples where needed.
