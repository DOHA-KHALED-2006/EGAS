@echo off
echo Starting EGAS Task Manager...
echo.
echo Open your web browser and go to: http://localhost:5000/seed
echo Then after seeding, go to: http://localhost:5000
echo.
echo Login credentials:
echo Manager: admin.manager@egas / 123
echo Employee: operations.emp@egas / 123
echo.
echo Press Ctrl+C to stop the server
echo.

cd /d "%~dp0"
venv\Scripts\python.exe app.py

pause
