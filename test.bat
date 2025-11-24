@echo off

:: start OYDVAT for testing
start OYDVAT.exe
:: let OYDVAT load
timeout 2
:: start a forbidden video
start https://www.youtube.com/shorts/7LocaReldQY
:: let oydvat do its job
timeout 6
:: end OYDVAT process, probably succeed
taskkill /f /im OYDVAT.exe
