Set-Location "C:\Users\marth\Documents\auditek"
Write-Host "Compilando Auditek..." -ForegroundColor Cyan
go build -o auditek.exe ./...
if ($LASTEXITCODE -eq 0) {
    Write-Host "Build completado exitosamente" -ForegroundColor Green
} else {
    Write-Host "Error durante la compilacion" -ForegroundColor Red
}
