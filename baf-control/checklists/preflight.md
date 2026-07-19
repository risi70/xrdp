# Preflight Checklist

Run before modifying code:

```sh
git status --short
git branch --show-current
git log --oneline -15
git fetch origin
git rev-parse HEAD
git rev-parse origin/mvp-broker-assertion
git log --oneline origin/mvp-broker-assertion..HEAD
git log --oneline HEAD..origin/mvp-broker-assertion
```

Stop if:

- the branch is not `mvp-broker-assertion`;
- local branch is behind remote;
- local/remote divergence is unclear;
- working tree contains unrelated changes.
