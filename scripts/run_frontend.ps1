Set-Location "$PSScriptRoot\..\frontend"
if (-not (Test-Path ".\node_modules")) {
  npm install --registry=https://registry.npmjs.org/
}
npm run dev
