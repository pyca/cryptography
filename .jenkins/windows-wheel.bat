wmic qfe
@set PATH="C:\Python27";"C:\Python27\Scripts";%PATH%
SET
if "%TOXENV%" == "py26" (
    @set PYTHON="C:\Python26\python.exe"
)
if "%TOXENV%" == "py27" (
    @set PYTHON="C:\Python27\python.exe"
)
if "%TOXENV%" == "py33" (
    @set PYTHON="C:\Python33\python.exe"
)
if "%TOXENV%" == "py34" (
    @set PYTHON="C:\Python34\python.exe"
)
if "%TOXENV%" == "py35" (
    @set PYTHON="C:\Python35\python.exe"
)
if "%TOXENV%" == "py36" (
    @set PYTHON="C:\Python36\python.exe"
)

@set py35orabove=true

if not "%TOXENV%" == "py35" (
    if not "%TOXENV%" == "py36" (
        @set py35orabove=false
    )
)

if "%py35orabove%" == "true" (
    if %label% == windows (
        @set INCLUDE="C:\OpenSSL-Win32-2015\include";%INCLUDE%
        @set LIB="C:\OpenSSL-Win32-2015\lib";%LIB%
    ) else (
        @set INCLUDE="C:\OpenSSL-Win64-2015\include";%INCLUDE%
        @set LIB="C:\OpenSSL-Win64-2015\lib";%LIB%
    )
) else (
    if %label% == windows (
        @set INCLUDE="C:\OpenSSL-Win32-2010\include";%INCLUDE%
        @set LIB="C:\OpenSSL-Win32-2010\lib";%LIB%
    ) else (
        @set INCLUDE="C:\OpenSSL-Win64-2010\include";%INCLUDE%
        @set LIB="C:\OpenSSL-Win64-2010\lib";%LIB%
    )
)

virtualenv -p %PYTHON% .release
call .release\Scripts\activate
pip install wheel virtualenv
pip wheel cryptography --wheel-dir=wheelhouse --no-use-wheel
for %%x in (wheelhouse\*.whl) do (
   pip install %%x
)
python -c "from cryptography.hazmat.backends.openssl.backend import backend;print('Loaded: ' + backend.openssl_version_text());print('Linked Against: ' + backend._ffi.string(backend._lib.OPENSSL_VERSION_TEXT).decode('ascii'))"
