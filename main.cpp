#include <iostream>
#include <Windows.h>
#include <chrono>
#include <iomanip>

#define RESET_COLOR SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
#define RED SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
#define GREEN SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
#define YELLOW SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_RED);
#define BLUE SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_INTENSITY);

using namespace std;

int InjectDLL(DWORD, char*);
int getDLLpath(char*);
int getPID(int*);
int getProc(HANDLE*, DWORD);
bool isValidDLLPath(const std::string& path);
void startupmenu();
void cleanermenu();
void prochackMenu();
void resizeTerminal(int height, int width);
void logMessage(const string& message, const string& type);

void clearScreen() {
    system("cls");
}

int main() {
    //checkAdminRights();

    while (true) {
        main_point:
        clearScreen();
        int PID, handler;
        char dll[255];
        SetConsoleTitle("AlacrityClient | discord.gg/z85MaK5vDW");
        resizeTerminal(80, 240);
        startupmenu();
        YELLOW;
        cout << "user@AlacBeta > ";
        RESET_COLOR;
        cin >> handler;

        if (handler == 1) {
            getDLLpath(dll);
            getPID(&PID);
            InjectDLL(PID, dll);
        }
        else if (handler == 2) {
            clearScreen();
            cleanermenu();
            handler = NULL;
            cout << endl;
            YELLOW;
            cout << "user@AlacBeta > ";
            RESET_COLOR;
            cin >> handler;
            if (handler == 1) 
            {
                clearScreen();
                prochackMenu();
                cout << endl;
                handler = NULL;
                YELLOW;
                cout << "user@AlacBeta > ";
                RESET_COLOR;
            }

            system("pause > nul");
        }
        else if (handler == 3) {
            cout << "Alacrity Client [Version 1.014.12]\n(c) Alacirty Client 2024. All rights reserved.\nserver: https://discord.gg/z85MaK5vDW\n";
            system("pause > nul");
        }
        
    }

    return 0;
}

void logMessage(const string& message, const string& type) {
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    tm local_time;
    localtime_s(&local_time, &now_time);

    cout << type << " | [" << put_time(&local_time, "%H:%M:%S") << "] " << message << endl;
}

void checkAdminRights() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    DWORD dwSize = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te;
        dwSize = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, dwSize, &dwSize)) {
            isAdmin = te.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isAdmin) {
        cout << "This program must be run as an administrator." << endl;
        system("pause");
        exit(0);
    }
}

void resizeTerminal(int height, int width) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD bufferSize = { static_cast<SHORT>(width), static_cast<SHORT>(height) };
    SetConsoleScreenBufferSize(hConsole, bufferSize);
    SMALL_RECT windowSize = { 0, 0, static_cast<SHORT>(width - 1), static_cast<SHORT>(height - 1) };
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
}

bool isValidDLLPath(const std::string& path) {
    DWORD fileAttr = GetFileAttributesA(path.c_str());
    return (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY));
}

int getDLLpath(char* dll) {
    dllstart:
    YELLOW;
    cout << "Enter path to DLL > ";
    RESET_COLOR;
    cin >> dll;

    if (!isValidDLLPath(dll)) {
        RED;
        logMessage("Invalid DLL path. Please check the path and try again.", "[!!!]");
        RESET_COLOR;
        goto dllstart;
    }

    return 1;
}

int getPID(int* PID) {
    YELLOW;
    cout << "Enter process PID > ";
    RESET_COLOR;
    cin >> *PID;
    cout << endl;
    return 1;
}

int InjectDLL(DWORD PID, char* dll) {
    HANDLE handleToProc;
    LPVOID LoadLibAddr;
    LPVOID baseAddr;
    HANDLE remThread;

    // Получить длину DLL
    int dllLength = strlen(dll) + 1;

    // Получаем обработку процесса
    if (getProc(&handleToProc, PID) < 0) {
        return -1;
    }

    // Загружаем kernel32
    LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    if (!LoadLibAddr) {
        RED;
        logMessage("Failed to get LoadLibrary address", "[!!!]");
        RESET_COLOR;
        cout << endl;
        system("pause > nul");
        return -1;
    }

    baseAddr = VirtualAllocEx(handleToProc, NULL, dllLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!baseAddr) {
        RED;
        logMessage("Failed to allocate memory in target process", "[!!!]");
        RESET_COLOR;
        cout << endl;
        system("pause > nul");
        return -1;
    }
    GREEN;
    logMessage("Memory allocated in target process", "[+]");
    RESET_COLOR;

    // Записываем путь к dll
    if (!WriteProcessMemory(handleToProc, baseAddr, dll, dllLength, NULL)) {
        RED;
        logMessage("Failed to write DLL path to target process", "[!!!]");
        RESET_COLOR;
        cout << endl;
        system("pause > nul");
        return -1;
    }
    GREEN;
    logMessage("DLL path written to target process", "[+]");
    RESET_COLOR;

    // Создаем удаленный поток
    remThread = CreateRemoteThread(handleToProc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, baseAddr, 0, NULL);

    if (!remThread) {
        RED;
        logMessage("Failed to create remote thread", "[!!!]");
        RESET_COLOR;
        cout << endl;
        system("pause > nul");
        return -1;
    }
    GREEN;
    logMessage("Remote thread created successfully", "[+]");
    RESET_COLOR;

    WaitForSingleObject(remThread, INFINITE);
    VirtualFreeEx(handleToProc, baseAddr, dllLength, MEM_RELEASE);

    // Закрываем обработчик
    if (CloseHandle(remThread) == 0) {
        RED;
        logMessage("Failed to close handle of remote thread", "[!!!]");
        RESET_COLOR;
        cout << endl;
        system("pause > nul");
        return -1;
    }

    if (CloseHandle(handleToProc) == 0) {
        RED;
        logMessage("Failed to close handle of target process", "[!!!]");
        RESET_COLOR;
        cout << endl;
        system("pause > nul");
        return -1;
    }

    GREEN;
    logMessage("DLL injection completed successfully", "[+]");
    RESET_COLOR;
    cout << endl;
    system("pause > nul");
    return 0;
    
    
}

int getProc(HANDLE* handleToProc, DWORD pid) {
    *handleToProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    if (*handleToProc == NULL) {
        RED;
        logMessage("Unable to open process", "[!!!]");
        RESET_COLOR;
        cout << endl;
        system("pause > nul");
        return -1;
    }
    else {
        GREEN;
        logMessage("Successfully opened process", "[+]");
        RESET_COLOR;
        return 1;
    }
}

void startupmenu() {
    cout << R"(
                      :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:        |
             :!~::!H!<   ~.U$X!?R$$$$$$$$MM!        | [1] Inject Dll
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!        | [2] Cleaner <beta>
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!        | [3] About
               ~?WuxiW*`   `"#$$$$8!!!!??!!!        | 
             :X- M$$$$       `"T#$T~!8$WUXU~        
            :%`  ~#$$$m:        ~!~ ?$$$$$$
          :!`.-   ~T$$$$8xx.  .xWW- ~""##*"          /$$$$$$  /$$                               /$$   /$$              
.....   -~~:<` !    ~?T#$$@@W@*?$$      /`          /$$__  $$| $$                              |__/  | $$              
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :           | $$  \ $$| $$  /$$$$$$   /$$$$$$$  /$$$$$$  /$$ /$$$$$$   /$$   /$$
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`           | $$$$$$$$| $$ |____  $$ /$$_____/ /$$__  $$| $$|_  $$_/  | $$  | $$
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~            | $$__  $$| $$  /$$$$$$$| $$      | $$  \__/| $$  | $$    | $$  | $$
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `               | $$  | $$| $$ /$$__  $$| $$      | $$      | $$  | $$ /$$| $$  | $$
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!                  | $$  | $$| $$|  $$$$$$$|  $$$$$$$| $$      | $$  |  $$$$/|  $$$$$$$
$R@i.~~ !     :   ~$$$$$B$$en:``                   |__/  |__/|__/ \_______/ \_______/|__/      |__/   \___/   \____  $$
?MXT@Wx.~    :     ~"##*$$$$M~                                                                                /$$  | $$          
                                                                                                             |  $$$$$$/          
                                                                                                              \______/                               
    )" << endl << endl;
}

void cleanermenu()
{
    cout << R"(
                      :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:        |
             :!~::!H!<   ~.U$X!?R$$$$$$$$MM!        | [1] Process Hacker Cleaner
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!        | [2] Last Activity Cleaner
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!        | [3] back
               ~?WuxiW*`   `"#$$$$8!!!!??!!!        | 
             :X- M$$$$       `"T#$T~!8$WUXU~        
            :%`  ~#$$$m:        ~!~ ?$$$$$$
          :!`.-   ~T$$$$8xx.  .xWW- ~""##*"          /$$$$$$  /$$                               /$$   /$$              
.....   -~~:<` !    ~?T#$$@@W@*?$$      /`          /$$__  $$| $$                              |__/  | $$              
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :           | $$  \ $$| $$  /$$$$$$   /$$$$$$$  /$$$$$$  /$$ /$$$$$$   /$$   /$$
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`           | $$$$$$$$| $$ |____  $$ /$$_____/ /$$__  $$| $$|_  $$_/  | $$  | $$
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~            | $$__  $$| $$  /$$$$$$$| $$      | $$  \__/| $$  | $$    | $$  | $$
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `               | $$  | $$| $$ /$$__  $$| $$      | $$      | $$  | $$ /$$| $$  | $$
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!                  | $$  | $$| $$|  $$$$$$$|  $$$$$$$| $$      | $$  |  $$$$/|  $$$$$$$
$R@i.~~ !     :   ~$$$$$B$$en:``                   |__/  |__/|__/ \_______/ \_______/|__/      |__/   \___/   \____  $$
?MXT@Wx.~    :     ~"##*$$$$M~                                                                                /$$  | $$          
                                                                                                             |  $$$$$$/          
                                                                                                              \______/                               
)" << endl;
}

void prochackMenu()
{
    cout << R"(
                      :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:        |
             :!~::!H!<   ~.U$X!?R$$$$$$$$MM!        | [1] Process Hacker Cleaner
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!        | [2] Last Activity Cleaner
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!        | [3] back
               ~?WuxiW*`   `"#$$$$8!!!!??!!!        | 
             :X- M$$$$       `"T#$T~!8$WUXU~        
            :%`  ~#$$$m:        ~!~ ?$$$$$$
          :!`.-   ~T$$$$8xx.  .xWW- ~""##*"          /$$$$$$  /$$                               /$$   /$$              
.....   -~~:<` !    ~?T#$$@@W@*?$$      /`          /$$__  $$| $$                              |__/  | $$              
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :           | $$  \ $$| $$  /$$$$$$   /$$$$$$$  /$$$$$$  /$$ /$$$$$$   /$$   /$$
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`           | $$$$$$$$| $$ |____  $$ /$$_____/ /$$__  $$| $$|_  $$_/  | $$  | $$
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~            | $$__  $$| $$  /$$$$$$$| $$      | $$  \__/| $$  | $$    | $$  | $$
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `               | $$  | $$| $$ /$$__  $$| $$      | $$      | $$  | $$ /$$| $$  | $$
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!                  | $$  | $$| $$|  $$$$$$$|  $$$$$$$| $$      | $$  |  $$$$/|  $$$$$$$
$R@i.~~ !     :   ~$$$$$B$$en:``                   |__/  |__/|__/ \_______/ \_______/|__/      |__/   \___/   \____  $$
?MXT@Wx.~    :     ~"##*$$$$M~                                                                                /$$  | $$          
                                                                                                             |  $$$$$$/          
                                                                                                              \______/                               
)" << endl;
}
