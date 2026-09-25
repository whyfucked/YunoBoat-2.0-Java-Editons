// language: C, file: launcher.c, target: Windows 10/11 x64, MSVC + mingw
// One-time launcher for perfboost.jar. GUI subsystem (no console).
// 1. Resolves javaw: bundled jvm\bin\javaw.exe, then %JAVA_HOME%, then PATH.
// 2. If no JVM at all: silently downloads a JRE (Adoptium) into <exedir>\jvm,
//    extracts with tar, locates the nested javaw.exe. All hidden, no prompt.
// 3. Spawns `javaw -jar perfboost.jar [args]` hidden + detached and exits.
//
// Build (MSVC):  cl /nologo /O2 /MT /Fe:perfboost.exe launcher.c /link /SUBSYSTEM:WINDOWS user32.lib urlmon.lib
// Build (mingw): x86_64-w64-mingw32-gcc -O2 -s -mwindows launcher.c -luser32 -lurlmon
#include <windows.h>
#include <urlmon.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "urlmon.lib")

static const char* kJar   = "perfboost.jar";
static const char* kJreUrl =
    "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse";

static void app_dir(char* out) {
    wchar_t wself[MAX_PATH] = {0};
    char self[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, wself, MAX_PATH);
    WideCharToMultiByte(CP_UTF8, 0, wself, -1, self, MAX_PATH, NULL, NULL);
    lstrcpyn(out, self, MAX_PATH);
    char* s = strrchr(out, '\\');
    if (s) *s = 0;
}

// Candidate javaw.exe in priority order; writes into buf, returns buf or "".
static char* find_javaw(char* buf) {
    char dir[MAX_PATH]; app_dir(dir);
    lstrcpy(buf, dir); lstrcat(buf, "\\jvm\\bin\\javaw.exe");
    if (GetFileAttributesA(buf) != INVALID_FILE_ATTRIBUTES) return buf;
    if (GetEnvironmentVariableA("JAVA_HOME", buf, MAX_PATH) > 0) {
        lstrcat(buf, "\\bin\\javaw.exe");
        if (GetFileAttributesA(buf) != INVALID_FILE_ATTRIBUTES) return buf;
    }
    if (SearchPathA(NULL, "javaw.exe", NULL, MAX_PATH, buf, NULL)) return buf;
    if (SearchPathA(NULL, "java.exe", NULL, MAX_PATH, buf, NULL)) return buf;
    return "";
}

// Search <javadir>\*\bin\javaw.exe (jre extracts into a versioned subdir).
static char* find_bundled_javaw(const char* javadir, char* buf) {
    char pat[MAX_PATH]; wsprintfA(pat, "%s\\*", javadir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return "";
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            char b[MAX_PATH];
            wsprintfA(b, "%s\\%s\\bin\\javaw.exe", javadir, fd.cFileName);
            if (GetFileAttributesA(b) != INVALID_FILE_ATTRIBUTES) {
                FindClose(h);
                lstrcpy(buf, b);
                return buf;
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return "";
}

static int run_wait(const char* cmd) {
    STARTUPINFOA si; ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    char buf[2048];
    lstrcpyn(buf, cmd, sizeof(buf));
    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 0;
    WaitForSingleObject(pi.hProcess, 300000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0 ? 1 : 0;
}

// Silent JRE download + extract into dir. Returns 1 on success.
static int install_jre(const char* dir) {
    char zip[MAX_PATH]; wsprintfA(zip, "%s\\jre.zip", dir);
    char ua[MAX_PATH]; lstrcpy(ua, "Mozilla/5.0");
    (void)ua;
    if (FAILED(URLDownloadToFileA(NULL, kJreUrl, zip, 0, NULL)))
        return 0;
    if (GetFileAttributesA(zip) == INVALID_FILE_ATTRIBUTES) return 0;

    // Primary: bsdtar on Win11 handles zip. Fallback: powershell Expand-Archive.
    char cmd[MAX_PATH * 2 + 64];
    wsprintfA(cmd, "tar -xf \"%s\" -C \"%s\"", zip, dir);
    if (!run_wait(cmd)) {
        wsprintfA(cmd, "powershell -NoProfile -WindowStyle Hidden -Command \"Expand-Archive -LiteralPath '%s' -DestinationPath '%s' -Force\"", zip, dir);
        run_wait(cmd);
    }
    DeleteFileA(zip);
    SetFileAttributesA(dir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    return 1;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    char dir[MAX_PATH]; app_dir(dir);
    SetCurrentDirectoryA(dir);

    char jar[MAX_PATH]; lstrcpy(jar, dir); lstrcat(jar, "\\"); lstrcat(jar, kJar);

    char javaw[MAX_PATH];
    lstrcpy(javaw, find_javaw(javaw));
    if (javaw[0] == 0) {
        char jvm[MAX_PATH]; wsprintfA(jvm, "%s\\jvm", dir);
        if (install_jre(jvm))
            lstrcpy(javaw, find_bundled_javaw(jvm, javaw));
    }
    if (javaw[0] == 0) return 1; // could not obtain a JVM

    char cmd[MAX_PATH * 2 + 128];
    wsprintfA(cmd, "\"%s\" -jar \"%s\" %s", javaw, jar, lpCmdLine ? lpCmdLine : "");

    STARTUPINFOA si; ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS | HIGH_PRIORITY_CLASS,
                       NULL, dir, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }
    return 2;
}