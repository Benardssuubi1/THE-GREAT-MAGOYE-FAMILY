$line = Get-Content .\assets\hero-bg-line.txt
$b64 = $line -replace ".*url\('data:image/jpeg;base64,", "" -replace "'\).*", ""
[IO.File]::WriteAllText('.\assets\hero-bg-b64.txt', $b64)
Write-Output 'saved'
