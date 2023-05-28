#define _CRT_SECURE_NO_WARNINGS
#include "backend.h"

//структуры процессов системы
process Processes[MAX_COUNT] = { 0 }; 
//количество запущенных процессов
size_t valid_proc_counter = 0;                      
//уровень мандатори для файла
WCHAR fileIntegrity[MAX_DETAILS_LENGTH] = { 0 };    

void getOwnerAndSid(HANDLE hProcess)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        fprintf(stdout, "[Error]: OpenProcessToken - %d \n", GetLastError());
        return;
    }

    DWORD tokenBufferSize = 0;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenBufferSize))
    {
        DWORD errorCode = GetLastError();
        if (errorCode != ERROR_INSUFFICIENT_BUFFER || tokenBufferSize == 0)
        {
            fprintf(stdout, "[Error]: GetTokenInformation - %d \n", GetLastError());
            CloseHandle(hToken);
            return;
        }
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(tokenBufferSize * sizeof(BYTE));
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, tokenBufferSize, &tokenBufferSize))
    {
        fprintf(stdout, "[Error]: GetTokenInformation - %d \n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    DWORD sidSize = SECURITY_MAX_SID_SIZE;
    PSID pSid = (PSID)malloc(sidSize * sizeof(BYTE));
    if (pSid == NULL)
    {
        fprintf(stdout, "[Error]: malloc - %d \n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    if (!CopySid(sidSize, pSid, pTokenUser->User.Sid))
    {
        fprintf(stdout, "[Error]: CopySid - %d \n", GetLastError());
        free(pSid);
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    LPWSTR str_Sid;
    ConvertSidToStringSid(pSid, &str_Sid);
    wcscpy(Processes[valid_proc_counter].SID, str_Sid);

    TCHAR processName[MAX_NAME_LENGTH];
    DWORD nameSize = MAX_NAME_LENGTH;
    TCHAR domain[MAX_NAME_LENGTH];
    DWORD domainSize = MAX_NAME_LENGTH;
    SID_NAME_USE sidUse;

    if (!LookupAccountSid(NULL, pSid, processName, &nameSize, domain, &domainSize, &sidUse))
    {
        fprintf(stdout, "[Error]: LookupAccountSid - %d \n", GetLastError());
        free(pSid);
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    wcsncpy(Processes[valid_proc_counter].processOwner, processName, nameSize);

    CloseHandle(hToken);
}

void getDepAndAslr(HANDLE hProcess)
{
    PROCESS_MITIGATION_DEP_POLICY dep = { 0 };
    PROCESS_MITIGATION_ASLR_POLICY aslr = { 0 };

    GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep));

    if (dep.Enable)
    {
        Processes[valid_proc_counter].DEP = TRUE;
        wcsncpy(Processes[valid_proc_counter].depDetails, TEXT("DEP (permanent)"), MAX_DETAILS_LENGTH);
    }
    else
    {
        Processes[valid_proc_counter].DEP = FALSE;
        wcsncpy(Processes[valid_proc_counter].depDetails, TEXT("DEP (disabled)"), MAX_DETAILS_LENGTH);
    }

    GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr));

    if (aslr.EnableBottomUpRandomization && aslr.EnableHighEntropy)
    {
        Processes[valid_proc_counter].ASLR = TRUE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR (high entropy)"), MAX_DETAILS_LENGTH);
    }
    else if (aslr.EnableBottomUpRandomization)
    {
        Processes[valid_proc_counter].ASLR = TRUE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR"), MAX_DETAILS_LENGTH);
    }
    else
    {
        Processes[valid_proc_counter].ASLR = FALSE;
        wcsncpy(Processes[valid_proc_counter].aslrDetails, TEXT("ASLR (disabled)"), MAX_DETAILS_LENGTH);
    }
}

void getParentPidAndName(DWORD processID)
{
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(h, &pe)) {
        do {
            if (pe.th32ProcessID == processID)
            {
                Processes[valid_proc_counter].parentPID = pe.th32ParentProcessID;
                HMODULE hMod;
                DWORD cbNeeded;
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Processes[valid_proc_counter].parentPID);

                if (!hProcess)
                {
                    CloseHandle(h);
                    return;
                }

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, Processes[valid_proc_counter].parentName,
                        sizeof(Processes[valid_proc_counter].parentName) / sizeof(WCHAR));
                }

                CloseHandle(hProcess);
                break;
            }
        } while (Process32Next(h, &pe));
    }

    CloseHandle(h);
}

void getProcName(HANDLE hProcess)
{
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleBaseName(hProcess, hMod, Processes[valid_proc_counter].processName, MAX_NAME_LENGTH);
    }
    //printf("Error: %d", GetLastError());
}

void getProcDlls(HANDLE hProcess)
{
    DWORD cbNeeded;
    HMODULE hMods[MAX_COUNT];

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count && i < MAX_COUNT; ++i)
        {
            if (GetModuleBaseName(hProcess, hMods[i], Processes[valid_proc_counter].processDllsName[i], MAX_NAME_LENGTH))
            {
                if (wcsstr(Processes[valid_proc_counter].processDllsName[i], TEXT("clr")) != NULL
                    || wcsstr(Processes[valid_proc_counter].processDllsName[i], TEXT("mscor")) != NULL)
                {
                    Processes[valid_proc_counter].CLR = TRUE;
                }
            }
        }
    }
}

void getProcPathToExe(HANDLE hProcess)
{
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleFileNameExW(hProcess, hMod, Processes[valid_proc_counter].pathProcessExe, MAX_PATH);
    }
}

void getProcType(HANDLE hProcess)
{
    BOOL Wow64Process = FALSE;
    if (!IsWow64Process(hProcess, &Wow64Process))
    {
        CloseHandle(hProcess);
        exit(EXIT_FAILURE);
    }

    if (!Wow64Process)
        wcsncpy(Processes[valid_proc_counter].procType, TEXT("64-bit"), MAX_TYPE_LENGTH);
    else
        wcsncpy(Processes[valid_proc_counter].procType, TEXT("32-bit"), MAX_TYPE_LENGTH);
}

void getProcDescryption(const wchar_t* fileName)
{
    int versionInfoSize = GetFileVersionInfoSize(fileName, NULL);
    if (!versionInfoSize)
    {
        fprintf(stdout, "[Error]: GetFileVersionInfoSize - %d\n", GetLastError());
        return;
    }

    BYTE* versionInfo = (BYTE*)malloc(versionInfoSize * sizeof(BYTE));
    if (versionInfo == NULL)
    {
        fprintf(stdout, "[Error]: malloc - %d\n", GetLastError());
        return;
    }

    if (!GetFileVersionInfo(fileName, NULL, versionInfoSize, versionInfo))
    {
        fprintf(stdout, "[Error]: GetTokenInformation - %d\n", GetLastError());
        return;
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *translationArray;

    UINT translationArrayByteLength = 0;
    if (!VerQueryValue(versionInfo, L"\\VarFileInfo\\Translation", (LPVOID*)&translationArray, &translationArrayByteLength))
    {
        fprintf(stdout, "[Error]: VerQueryValue - %d\n", GetLastError());
        return;
    }

    for (unsigned int i = 0; i < (translationArrayByteLength / sizeof(LANGANDCODEPAGE)); ++i)
    {
        wchar_t fileDescriptionKey[256];
        wsprintf(fileDescriptionKey, L"\\StringFileInfo\\%04x%04x\\FileDescription", translationArray[i].wLanguage, translationArray[i].wCodePage);

        TCHAR* descript = NULL;

        UINT fileDescriptionSize;
        VerQueryValue(versionInfo, fileDescriptionKey, (LPVOID*)&descript, &fileDescriptionSize);

        if (descript != NULL)
            wcsncpy(Processes[valid_proc_counter].procDescryption, descript, MAX_NAME_LENGTH);
    }
}

void processInfo(DWORD processID)
{
    Processes[valid_proc_counter].PID = processID;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    //printf("Error: %d", GetLastError());

    if (!hProcess)
    {
        return;
    }

    getOwnerAndSid(hProcess);

    getProcName(hProcess);

    getProcPathToExe(hProcess);

    getProcDescryption(Processes[valid_proc_counter].pathProcessExe);

    getProcDlls(hProcess);

    getProcType(hProcess);

    getParentPidAndName(processID);

    getIntegrityLevel(hProcess);

    getDepAndAslr(hProcess);

    /*fprintf(stdout, "procDescryption: %ws\n", Processes[valid_proc_counter].procDescryption);
    fprintf(stdout, "processName: %ws\n", Processes[valid_proc_counter].processName);
    fprintf(stdout, "PID: %lu\n", Processes[valid_proc_counter].PID);
    fprintf(stdout, "pathProcessExe: %ws\n", Processes[valid_proc_counter].pathProcessExe);
    fprintf(stdout, "processOwner: %ws\n", Processes[valid_proc_counter].processOwner);
    fprintf(stdout, "SID: %ws\n", Processes[valid_proc_counter].SID);
    fprintf(stdout, "procType: %ws\n", Processes[valid_proc_counter].procType);
    fprintf(stdout, "aslrDetails: %ws\n", Processes[valid_proc_counter].aslrDetails);
    fprintf(stdout, "depDetails: %ws\n", Processes[valid_proc_counter].depDetails);
    fprintf(stdout, "parentName: %ws\n", Processes[valid_proc_counter].parentName);
    fprintf(stdout, "parentPID: %lu\n", Processes[valid_proc_counter].parentPID);
    fprintf(stdout, "integrityLevel: %ws\n", Processes[valid_proc_counter].integrityLevel);
    fprintf(stdout, "____________________________________________________________________\n");*/

    CloseHandle(hProcess);
    ++valid_proc_counter;
}

void processesDatabase()
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        fprintf(stdout, "[Error]: EnumProcesses - %d \n", GetLastError());
        exit(EXIT_FAILURE);
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (size_t i = 0; i < cProcesses; ++i)
    {
        if (aProcesses[i] != 0)
        {
            processInfo(aProcesses[i]);
        }
    }
}

BOOL turnDebugPrivilege()
{
    HANDLE hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        printf("[Error]: OpenProcessToken - %d\n", GetLastError());
        return FALSE;
    }

    LUID luidDebug;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug))
    {
        printf("[Error]: LookupPrivilegeValue - %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidDebug;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // disable - 0

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("[Error]: AdjustTokenPrivileges - %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        fprintf(stdout, "[Error]: ERROR_NOT_ALL_ASSIGNED");
        CloseHandle(hToken);
        return TRUE;
    }

    CloseHandle(hToken);

    return TRUE;
}

void getIntegrityLevel(HANDLE hProcess)
{
    HANDLE hToken;
    DWORD returnLength;

    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken))
    {
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLength))
        {
            DWORD errorCode = GetLastError();
            if (errorCode != ERROR_INSUFFICIENT_BUFFER || returnLength == 0)
            {
                fprintf(stdout, "[Error]: GetTokenInformation - %d\n", GetLastError());
                CloseHandle(hToken);
                return;
            }

            PTOKEN_MANDATORY_LABEL pIntegrityLevel = (PTOKEN_MANDATORY_LABEL)malloc(returnLength);
            if (pIntegrityLevel != NULL)
            {
                if (GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLevel, returnLength, &returnLength))
                {
                    DWORD integrityLevel = *GetSidSubAuthority(pIntegrityLevel->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pIntegrityLevel->Label.Sid) - 1));

                    if (integrityLevel < SECURITY_MANDATORY_LOW_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("Untrusted"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel == SECURITY_MANDATORY_LOW_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("Low"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && integrityLevel < SECURITY_MANDATORY_HIGH_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("Medium"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID && integrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("High"), MAX_DETAILS_LENGTH);
                    }
                    else if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
                    {
                        wcsncpy(Processes[valid_proc_counter].integrityLevel, TEXT("System"), MAX_DETAILS_LENGTH);
                    }
                }
                free(pIntegrityLevel);
            }
        }
        CloseHandle(hToken);
    }
}

void changeProcIntegrity(DWORD processID, wchar_t* integrity)
{
    DWORD dwProcessId = processID;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
    if (hProcess == NULL)
    {
        printf("[Error]: OpenProcess - %d\n", GetLastError());
        return;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &hToken))
    {
        printf("[Error]: OpenProcessToken - %d\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    DWORD dwSize = 0;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize))
    {
        DWORD errorCode = GetLastError();
        if (errorCode != ERROR_INSUFFICIENT_BUFFER || dwSize == 0)
        {
            printf("[Error]: GetTokenInformation - %d\n", GetLastError());
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return;
        }
    }

    TOKEN_MANDATORY_LABEL* pIntegrityLabel = (TOKEN_MANDATORY_LABEL*)malloc(dwSize);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLabel, dwSize, &dwSize))
    {
        printf("[Error]: GetTokenInformation - %d\n", GetLastError());
        free(pIntegrityLabel);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }

    // Low (SID: S-1-16-4096), 
    // Medium (SID: S-1-16-8192) 
    // High (SID: S-1-16-12288) 
    // System (SID: S-1-16-16384)

    PSID levelSid = { 0 };
    if (!ConvertStringSidToSid((LPCWSTR)integrity, &levelSid))
    {
        printf("[Error]: ConvertStringSidToSid - %d\n", GetLastError());
        free(pIntegrityLabel);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }

    pIntegrityLabel->Label.Sid = levelSid;

    if (!SetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLabel, dwSize))
    {
        printf("[Error]: SetTokenInformation - %d\n", GetLastError());
        free(pIntegrityLabel);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }

    free(pIntegrityLabel);
    CloseHandle(hToken);
    CloseHandle(hProcess);
}

WCHAR* getFileIntegrityLevel(WCHAR* file_name)
{
    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL acl = 0;

    GetNamedSecurityInfo(file_name, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &acl, &pSD);

    if (0 != acl && 0 < acl->AceCount)
    {
        SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
        if (GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
        {
            SID* sid = reinterpret_cast<SID*>(&ace->SidStart);
            integrityLevel = sid->SubAuthority[0];
        }
    }

    PWSTR stringSD;
    ULONG stringSDLen = 0;

    ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);

    if (pSD) LocalFree(pSD);

    if (integrityLevel == 0x0000) wcscpy(fileIntegrity, L"Untrusted");
    else if (integrityLevel == 0x1000)  wcscpy(fileIntegrity, L"Low");
    else if (integrityLevel == 0x2000)  wcscpy(fileIntegrity, L"Medium");
    else if (integrityLevel == 0x3000) wcscpy(fileIntegrity, L"High");
    else if (integrityLevel == 0x4000) wcscpy(fileIntegrity, L"System");
    else wcscpy(fileIntegrity, L"Error");

    return fileIntegrity;
}

void changeFileIntegrityLevel(WCHAR* file_name, WCHAR* integrity)
{
    PSECURITY_DESCRIPTOR pSD = NULL;

    PACL pSacl = NULL;
    BOOL fSaclPresent = FALSE;
    BOOL fSaclDefaulted = FALSE;

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW((LPCWSTR)integrity, SDDL_REVISION_1, &pSD, NULL))
    {
        if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
        {
            if (SetNamedSecurityInfoW(file_name, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl))
            {
                fprintf(stdout, "[Error]: SetNamedSecurityInfoW - %d\n", GetLastError());
            }
        }
        else
        {
            fprintf(stdout, "[Error]: GetSecurityDescriptorSacl - %d\n", GetLastError());
        }
    }
    else
    {
        fprintf(stdout, "[Error]: ConvertStringSecurityDescriptorToSecurityDescriptorW - %d\n", GetLastError());
    }
    LocalFree(pSD);
}

void sendDatabase(HANDLE hPipe)
{
    DWORD dwRead;
    DWORD dwWritten;
    process Temp = { 0 };

    for (size_t i = 0; i < valid_proc_counter + 1; ++i)
    {
        while (1)
        {
            WriteFile(hPipe, &Processes[i], sizeof(Processes[i]), &dwWritten, NULL);

            if (ReadFile(hPipe, &Temp, sizeof(Temp), &dwRead, NULL) != FALSE)
            {
                if (wcscmp(Processes[i].processName, Temp.processName) == 0)
                {
                    break;
                }
            }
        }
    }
    WriteFile(hPipe, "DONE", 5, &dwWritten, NULL);

}

void establishPipe()
{
    HANDLE hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\Pipe"),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_TYPE_MESSAGE | PIPE_WAIT, //BYTE
        1,
        1024 * 16,
        1024 * 16,
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        fprintf(stdout, "[Error]: CreateNamedPipe - %d\n", GetLastError());
        return;
    }

    //////////////////////// GET DATABASE OF PROCESS //////////////////////////////

    turnDebugPrivilege();
    processesDatabase();

    //////////////////////// SEND DATABASE TO GUI //////////////////////////////

    DWORD dwRead = 0;
    DWORD dwWritten = 0;
    WCHAR buffer[128] = { 0 };

    //ожидание подключения графики
    while (1)
    {
        if (ConnectNamedPipe(hPipe, NULL) != FALSE)   
        {
            sendDatabase(hPipe);
        }
        while (1)
        {
            BOOL read = ReadFile(hPipe, buffer, sizeof(buffer), &dwRead, NULL);
            if (read != FALSE)
            {
                printf("Entered");
                int command = buffer[0] - 48; // 1 Low 4242
                WCHAR* context = { 0 };
                WCHAR* pointer = &buffer[2];
                WCHAR* integrity;
                WCHAR* procId;
                DWORD processID;
                WCHAR* fileName;
                WCHAR integrity_cmd[30] = {0};

                switch (command)
                {
                case DATABASE:
                    valid_proc_counter = 0;
                    processesDatabase();
                    sendDatabase(hPipe);
                    break;

                case CHANGE_INTEGRITY:
                    integrity = wcstok_s(pointer, L" \0", &context);
                    procId = wcstok_s(NULL, L" \0", &context);
                    processID = _wtoi(procId);

                    if (!wcscmp(integrity, L"Low")) wcscpy(integrity, L"S-1-16-4096");
                    else if (!wcscmp(integrity, L"Medium")) wcscpy(integrity, L"S-1-16-8192");
                    else wcscpy(integrity, L"S-1-16-12288");

                    changeProcIntegrity(processID, integrity);
                    break;

                case MANDATORY:
                    fileName = wcstok_s(pointer, L"\0", &context);
                    WCHAR fileInt[32];
                    WriteFile(hPipe, getFileIntegrityLevel(fileName), sizeof(fileInt), &dwWritten, NULL);

                    break;

                case CHANGE_MANDATORY:
                    integrity = wcstok_s(pointer, L" \0", &context);
                    fileName = wcstok_s(NULL, L" \0", &context);
                    if (!wcscmp(integrity, L"Low")) wcscpy(integrity_cmd, L"S:(ML;;NR;;;LW)");
                    else if (!wcscmp(integrity, L"Medium")) wcscpy(integrity_cmd, L"S:(ML;;NR;;;ME)");
                    else wcscpy(integrity_cmd, L"S:(ML;;NR;;;HI)");

                    changeFileIntegrityLevel(fileName, integrity_cmd);
                    break;

                case DISCONNECT:
                    DisconnectNamedPipe(hPipe);
                    CloseHandle(hPipe);
                    break;


                default:
                    break;
                }
            }
        }
    }
}

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");

    establishPipe();

    getFileIntegrityLevel((WCHAR*)L"C:\\Qt");

    //DWORD sePrivilege = SE_PRIVILEGE_ENABLED;
    //turnDebugPrivilege(sePrivilege);

    processesDatabase();

    return 0;
}