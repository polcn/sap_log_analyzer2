# setup_submodule.ps1
# Script to convert a nested repository to a proper Git submodule

param(
    [string]$RepoUrl = "https://github.com/polcn/sap_log_analyzer2.git",
    [string]$SubmodulePath = "sap_log_analyzer2",
    [switch]$Force = $false
)

Write-Host "SAP Audit Tool - Submodule Setup Script" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Verify we're in the right directory (repository root)
if (-not (Test-Path ".git")) {
    Write-Host "Error: This script should be run from the repository root directory." -ForegroundColor Red
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Red
    exit 1
}

# Check if the directory exists
if (-not (Test-Path $SubmodulePath)) {
    Write-Host "Error: Directory '$SubmodulePath' not found." -ForegroundColor Red
    exit 1
}

# Check if it's already a submodule
if (Test-Path ".gitmodules") {
    $moduleContent = Get-Content ".gitmodules" -Raw
    if ($moduleContent -match [regex]::Escape($SubmodulePath)) {
        Write-Host "'$SubmodulePath' is already configured as a submodule." -ForegroundColor Yellow
        
        if (-not $Force) {
            Write-Host "Use -Force to reconfigure it anyway." -ForegroundColor Yellow
            exit 0
        } else {
            Write-Host "Force flag set, reconfiguring submodule..." -ForegroundColor Yellow
        }
    }
}

# Check if it contains a .git directory (nested repository)
if (Test-Path "$SubmodulePath/.git") {
    Write-Host "Found nested repository in '$SubmodulePath'" -ForegroundColor Yellow
    
    # Confirm action
    if (-not $Force) {
        $confirmation = Read-Host "This will remove the nested repository configuration. Continue? (y/n)"
        if ($confirmation -ne "y") {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
    
    Write-Host "Removing nested repository configuration..." -ForegroundColor Yellow
    Remove-Item -Path "$SubmodulePath/.git" -Recurse -Force
}

# Remove from Git cache
Write-Host "Removing '$SubmodulePath' from Git cache..." -ForegroundColor Yellow
git rm -r --cached $SubmodulePath --quiet

# Add as a proper submodule
Write-Host "Adding '$SubmodulePath' as a Git submodule..." -ForegroundColor Green
$result = git submodule add $RepoUrl $SubmodulePath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error adding submodule: $result" -ForegroundColor Red
    Write-Host "Trying to recover..." -ForegroundColor Yellow
    
    # If the submodule add failed, try to initialize from scratch
    if (Test-Path ".gitmodules") {
        $moduleContent = Get-Content ".gitmodules" -Raw
        if ($moduleContent -match [regex]::Escape($SubmodulePath)) {
            git submodule init
            git submodule update
        }
    }
} else {
    Write-Host "Submodule added successfully." -ForegroundColor Green
}

# Instructions
Write-Host ""
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To initialize and update the submodule:" -ForegroundColor Cyan
Write-Host "  git submodule update --init --recursive" -ForegroundColor White
Write-Host ""
Write-Host "To update the submodule to the latest version:" -ForegroundColor Cyan
Write-Host "  git submodule update --remote" -ForegroundColor White
Write-Host ""
Write-Host "Don't forget to commit the .gitmodules file:" -ForegroundColor Cyan
Write-Host "  git add .gitmodules" -ForegroundColor White
Write-Host "  git commit -m 'Add sap_log_analyzer2 as submodule'" -ForegroundColor White
