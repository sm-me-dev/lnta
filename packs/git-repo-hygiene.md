---
id: git-repo-hygiene
name: Git Repository Hygiene
triggers:
  - git
  - repo
  - dirty
  - reflog
  - stash
  - rebase
  - merge
  - branch
  - hygiene
  - cleanup
allowed_paths:
  - "~/.config/lnta/*.md"
  - "~/.gitconfig"
  # Note: ~/.git/* is read-only diagnostics via inspect_system, not write_scoped_file
required_bins:
  - git
  - less
context_cmd: git --version
verify_cmd: git status --short | grep -q "${branch_name}" && echo "repo state verified"
---
# Git Repository Hygiene

Inspect dirty worktrees, reflog recovery, `.gitignore` rules, and safe rebase/stash diagnostics. Always work in read-only mode until explicitly approved for mutations.

## What this pack covers

- Checking current repo status with `git status`
- Diagnosing dirty working trees with `git status --short`
- Recovering from mistakes via `git reflog`
- Managing stashes with `git stash list`, `git stash show`, `git stash pop`
- Safe rebase diagnostics with `git rebase --abort`, `git merge --abort`
- Inspecting and editing `.gitignore` patterns
- Comparing branches with `git diff` and `git log --graph --oneline --all`
- Identifying large files with `git verify-pack -l` and `git-repack`
- Understanding worktrees with `git worktree list`

## Safety

**Critical**: Always start with read-only diagnostics (`inspect_system`). Never run `git push --force`, `git rebase`, or `git merge --ff` without explicit approval. All mutation operations require `mutate_system` with confirmation. This pack is read-only for inspection by default.

## Repo status diagnostics

```bash
# Check overall repo status
git status

# Short status (quick overview)
git status --short
# XY filename - changes staged
# M filename - changes not staged
# D filename - deleted (not staged)
# ?? filename - untracked

# Branch info
git status --branch

# Diff summary (staged vs unstaged)
git diff --stat
git diff --cached --stat
```

## Worktree diagnostics

### List existing worktrees
```bash
git worktree list
# main /path/to/repo
# feature/login /path/to/repo-feature-login (detached HEAD)
```

### Inspect each worktree
```bash
# Show current branch and status in each worktree
cd /path/to/repo && git worktree list -v

# Check for conflicts between worktrees
cd /path/to/repo-feature/login
git log --oneline main..HEAD  # commits only in this worktree

# Check if worktree is locked
git worktree lock  # Lock to prevent removal
git worktree unlock  # Unlock
```

### Remove a worktree (after merging)
```bash
# Remove the feature branch worktree
git worktree remove /path/to/repo-feature/login
```

## Reflog recovery

### View the full reflog
```bash
# Current branch reflog
git reflog

# All refs reflog
git reflog --all

# Remote tracking reflog
git reflog origin/main
```

### Recover a lost commit
```bash
# Find the commit hash
git reflog --all | grep "lost/desired"

# Recover the commit
git reflog --all
# Example: git checkout -b recovered abc123def

# Or more directly
git log --all --oneline | head -20
# Find the hash you want, then
git checkout -b new-branch abc123def
```

### Recover a deleted branch
```bash
# List reflog entries with branch names
git reflog --all --format="%h %cr %s"

# Checkout the entry you want
git checkout <old-branch-name>@{<n>}  # e.g. git checkout main@{1}
# Or
git checkout -b recovered-branch <hash>
```

## Stash management

### List all stashes
```bash
git stash list
# stash@{0}: WIP on main: abc123def message
# stash@{1}: WIP on feature/login: def456abc message
```

### Show stash contents
```bash
git stash show -p stash@{0}  # Unified diff
git stash show stash@{0}     # Summary of changed files
```

### Pop vs apply
```bash
# Apply and remove (default)
git stash pop

# Apply without removing
git stash apply stash@{0}

# Apply a specific stash to current branch
git stash branch new-branch-name stash@{0}  # Creates new branch with stash applied
```

### Drop a stash
```bash
git stash drop stash@{0}  # Remove without applying
git stash list -i  # Interactive drop (new git versions)
```

## Safe rebase and merge diagnostics

### Always prefer `--no-ff` or squash over `--rebase` in shared branches

### Rebase a feature branch onto main (local, safe)
```bash
# 1. Ensure clean working tree
git status  # nothing to commit, working tree clean

# 2. Rebase onto latest main
git rebase main  # or git rebase origin/main

# 3. Resolve conflicts if any (edit, then git add, then git rebase --continue)

# 4. Verify
git log --oneline main..HEAD  # Show new commits

# If rebase goes wrong:
git rebase --abort  # Restore to pre-rebase state
```

### Abort a merge
```bash
git merge --abort  # Returns to pre-merge state
# Or manually:
git reset --hard HEAD
```

## .gitignore best practices

### Common patterns

```gitignore
# Dependencies
node_modules/
vendor/
target/
__pycache__/
*.egg-info/

# OS generated
.DS_Store
Thumbs.db

# User-specific
*.env
*.pem
*.key
*.crt

# Build artifacts
*.o
*.so
*.pyc
*.pyo
*.egg

# IDEs
.vscode/
.idea/
*.swp
*~

# Large files (use Git LFS instead)
*.lock
*.dat
*.h5

# VCS
.git/
```

### .gitignore anti-patterns

```gitignore
# BAD - never ignore .gitignore itself
!.gitignore

# BAD - ignore .env.example but not .env
.env.example
# (better: .env*)
```

## Common workflows

### Clean up after feature work
```bash
# 1. Ensure work on feature is done and merged
git checkout main
git pull

# 2. Delete feature branch locally
git branch -d feature-login  # fast-forward delete
# or
git branch -D feature-login  # force delete (unmerged)

# 3. Remove remote feature branch
git push origin --delete feature-login

# 4. Clean up stale worktrees
git worktree list  # Check for stale entries
git worktree remove /path/to/repo-feature-login

# 5. Run hygiene checks
git status --short
git reflog expire --expire=now --all
git gc --prune=now
```

### Recover from accidental hard reset
```bash
# If you did git reset --hard HEAD~3 and lost commits
# 1. Immediately stop and check reflog
git reflog --all

# 2. Find the commit before the reset
# Suppose it was at abc123def before the reset
git checkout -b recovered HEAD@{3}  # Or use the hash from reflog

# 3. Or simply
git checkout -b recovered <hash-from-reflog>
```

### Fix dirty working tree before important operation
```bash
# Stash uncommitted changes
git stash push -u  # Stash untracked too

# Verify stash
git stash list

# Proceed with operation (rebase, merge, checkout)
git rebase main

# Pop stash when done
git stash pop
```

### Identify large/unnecessary files
```bash
# Find large tracked files in repo history
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(rest)' | while read t n r; do
  if [ "$t" = "blob" ]; then
    s=$(git cat-file -s "$n")
    echo "$s $n"
  fi
done | sort -k1 -n -r | head -20

# Or simpler
git ls-files -s | while read mode type hash path; do
  git cat-file -s "$hash" | head -c 100  # Preview first 100 bytes
done
```

### Check for gitignore-untracked files accumulating
```bash
# List all untracked files
git status --porcelain | grep '^??' | wc -l

# See what's taking up space
git count-objects -v  # Show pack stats
```

## Verification

The `verify_cmd` checks that `git status --short` contains entries matching the current branch name (i.e., the repo is in a known state). After running any git operations, verify the repo state is as expected. Always check `git status` and `git log --oneline -5` before and after major operations to ensure nothing unexpected happened.