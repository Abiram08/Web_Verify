# Cleanup script for WebVerify project

Write-Host "Starting cleanup of unnecessary files..." -ForegroundColor Yellow

# Essential files and directories that should NOT be deleted
$essentialFiles = @(
    "app.py",
    "predictor.py",
    "model.pkl",
    "requirements.txt",
    "README.md",
    "LICENSE",
    ".gitignore",
    "Templates",
    "Templates\index.html",
    "tests",
    "tests\test_predictor.py",
    "uploads"
)

# Delete all CSV files in Models directory (they can be regenerated or downloaded when needed)
Write-Host "Removing CSV files from Models directory..." -ForegroundColor Cyan
Remove-Item -Path ".\Models\*.csv" -Force

# Clean Python cache files
Write-Host "Removing Python cache files..." -ForegroundColor Cyan
Remove-Item -Path ".\**\__pycache__" -Force -Recurse
Remove-Item -Path ".\*.pyc" -Force
Remove-Item -Path ".\*.pyo" -Force
Remove-Item -Path ".\*.pyd" -Force

# Clean virtual environment if it exists
if (Test-Path ".\.venv") {
    Write-Host "Removing virtual environment..." -ForegroundColor Cyan
    Remove-Item -Path ".\.venv" -Force -Recurse
}
if (Test-Path ".\env") {
    Remove-Item -Path ".\env" -Force -Recurse
}

# Clean IDE specific files
Write-Host "Removing IDE specific files..." -ForegroundColor Cyan
Remove-Item -Path ".\.vscode" -Force -Recurse
Remove-Item -Path ".\.idea" -Force -Recurse
Remove-Item -Path ".\.vs" -Force -Recurse

# Clean test cache
Write-Host "Removing test cache..." -ForegroundColor Cyan
Remove-Item -Path ".\.pytest_cache" -Force -Recurse
Remove-Item -Path ".coverage" -Force
Remove-Item -Path ".\htmlcov" -Force -Recurse

# Clean log files
Write-Host "Removing log files..." -ForegroundColor Cyan
Remove-Item -Path ".\*.log" -Force

# Clean contents of uploads directory but keep the directory
Write-Host "Cleaning uploads directory..." -ForegroundColor Cyan
Get-ChildItem -Path ".\uploads\*" -File | Remove-Item -Force

Write-Host "`nCleanup complete!" -ForegroundColor Green
Write-Host "`nThe following essential files have been kept:" -ForegroundColor Green
$essentialFiles | ForEach-Object { Write-Host "- $_" }

Write-Host "`nNote: If you need to recreate the virtual environment, run:" -ForegroundColor Yellow
Write-Host "python -m venv .venv" -ForegroundColor Gray
Write-Host ".\venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "pip install -r requirements.txt" -ForegroundColor Gray