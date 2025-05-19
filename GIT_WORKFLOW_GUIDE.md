# SAP Log Analyzer Git Workflow Guide

This guide provides instructions for managing the SAP Log Analyzer codebase across your local Git repository and GitHub.

## Repository Structure

```
C:/Users/craig/OneDrive/Documents/Python/  (Main repository)
├── .git/                                  (Git repository files)
├── .github/                               (GitHub configuration files)
├── README.md                              (Project documentation)
├── CHANGELOG.md                           (Version history)
├── SAP_Audit_Tool_Technical_Reference.md  (Technical documentation)
├── [Python source files]                  (Main project files)
├── sap_log_analyzer2/                     (Nested directory with its own Git repository)
│   └── .git/                              (Nested Git repository - causing conflicts)
└── [Other directories]
```

**Note about nested repository**: The `sap_log_analyzer2` directory contains its own `.git` directory, making it a "nested repository" that can cause Git index conflicts. This is why you may experience errors when trying to commit changes that involve this directory.

## Normal Git Workflow

For making changes to files in the main repository:

1. Edit the desired files
2. Stage the changes: `git add [filename]`
3. Commit the changes: `git commit -m "Descriptive message"`
4. Push to GitHub: `git push`

## Handling the Nested Repository

To avoid conflicts with the nested repository in `sap_log_analyzer2`:

### Option 1: Ignore the nested repository (simplest)

1. Add `sap_log_analyzer2/` to your `.gitignore` file
2. Manage the nested repository separately

### Option 2: Convert the nested repository to a submodule (advanced)

1. Remove the nested repository from the index: `git rm --cached sap_log_analyzer2`
2. Add it as a proper Git submodule: `git submodule add [url] sap_log_analyzer2`
3. Commit this change: `git commit -m "Convert nested repo to submodule"`

### Option 3: Merge the repositories (complex)

1. Backup both repositories
2. Remove the `.git` directory from the nested repository
3. Add all files from the formerly nested repository to the main one
4. Commit the changes

## Step-by-Step Workflow for Code Changes

### 1. Before making changes

```powershell
# Navigate to your repository
cd C:\Users\craig\OneDrive\Documents\Python

# Make sure you have the latest changes
git pull

# Check current status
git status
```

### 2. Making and staging changes

```powershell
# After editing files, check what's changed
git status

# Add specific files
git add filename.py

# Add all changed files (except those in .gitignore)
git add .

# Check what's staged
git status
```

### 3. Committing changes

```powershell
# Commit with a descriptive message
git commit -m "Brief description of changes"

# For more detailed commit messages
git commit
# (This opens an editor where you can type a longer message)
```

### 4. Pushing to GitHub

```powershell
# Push commits to the remote repository
git push
```

### 5. Resolving common issues

#### Git GUI index error

If you see "Updating the Git Index failed" with an error about `sap_log_analyzer2` being a directory:

1. Click "Rescan" in Git GUI
2. If that doesn't work, click "Unlock Index"
3. If problems persist, try the command line:

```powershell
# Force index update
git update-index --refresh

# Check for errors
git fsck
```

#### Handling merge conflicts

If you get merge conflicts when pulling:

1. Open the conflicted files (they'll be marked in the status)
2. Look for conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`)
3. Edit the files to resolve conflicts
4. Add the resolved files: `git add [filename]`
5. Complete the merge: `git commit`

## Keeping Documentation Updated

When making code changes, remember to update these files as needed:

1. **README.md** - For high-level changes and new features
2. **CHANGELOG.md** - For version updates and detailed change lists
3. **SAP_Audit_Tool_Technical_Reference.md** - For technical implementation details
4. **REPORT_GUIDE.md** - For changes that affect report output and interpretation
5. **dynamic_field_handling.md** - For changes to the field mapping system

## Best Practices

1. **Commit messages** should be clear and descriptive
2. **Pull before pushing** to avoid merge conflicts
3. **Review changes with `git diff`** before committing
4. **Group related changes** into single, logical commits
5. **Update documentation** along with code changes
6. **Test your changes** before pushing to GitHub

## GitHub Repository Management

### Checking remote repository

```powershell
# List remote repositories
git remote -v

# Show details about the origin remote
git remote show origin
```

### Branch management

```powershell
# List all branches
git branch -a

# Create a new branch
git checkout -b [branch-name]

# Switch to a different branch
git checkout [branch-name]

# Merge a branch into current branch
git merge [branch-name]
```

## Troubleshooting Tips

### 1. Git GUI doesn't show expected files

Try using command line Git to get more detailed error messages:

```powershell
git status
```

### 2. Can't stage certain files

Check if the files are in a nested Git repository:

```powershell
# Look for .git directories
Get-ChildItem -Path . -Recurse -Force -Directory -Hidden | Where-Object { $_.Name -eq ".git" }
```

### 3. Push errors

If you encounter errors pushing to GitHub:

```powershell
# Check if your remote is correctly configured
git remote -v

# Pull any changes first
git pull

# If you need to force push (use with caution!)
git push --force
```

### 4. Reset to a clean state

If things get too confusing and you want to start fresh:

```powershell
# Discard all local changes (CAUTION: cannot be undone)
git reset --hard HEAD

# Discard changes for a specific file
git checkout -- [filename]
```

## Summary

1. Navigate to `C:\Users\craig\OneDrive\Documents\Python`
2. Make your code changes
3. Stage changes with `git add .` or `git add [filename]`
4. Commit changes with `git commit -m "Description"`
5. Push to GitHub with `git push`
6. Be aware of the nested repository in `sap_log_analyzer2` and avoid index conflicts
