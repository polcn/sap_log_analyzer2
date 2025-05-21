# git_save.ps1
# Quick script to stage, commit, and push changes to Git

param(
    [string]$CommitMessage = "Update SAP Audit Tool - $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    [switch]$NoPush = $false
)

# Navigate to the repository directory
Set-Location "C:\Users\craig\OneDrive\Documents\Python"

# Display current status before changes
Write-Host "Current Git Status:" -ForegroundColor Cyan
git status

# Stage all changes
Write-Host "`nStaging changes..." -ForegroundColor Yellow
git add .

# Show what's been staged
Write-Host "`nStaged changes:" -ForegroundColor Green
git status

# Commit the changes
Write-Host "`nCommitting changes with message: $CommitMessage" -ForegroundColor Yellow
git commit -m "$CommitMessage"

# Push the changes if NoPush is not specified
if (-not $NoPush) {
    Write-Host "`nPushing changes to remote repository..." -ForegroundColor Yellow
    git push
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nSuccessfully pushed to GitHub!" -ForegroundColor Green
    } else {
        Write-Host "`nPush failed. You may need to pull changes first or resolve conflicts." -ForegroundColor Red
        Write-Host "Try running: git pull" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nChanges committed but not pushed. Run 'git push' manually when ready." -ForegroundColor Yellow
}

# Final status
Write-Host "`nCurrent repository status:" -ForegroundColor Cyan
git status
