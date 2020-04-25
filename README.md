# 调用exe内部函数.net版

之前写了个c++主程序调用一个exe内部函数的例子，现在改用.net当主程序实现，主要是实现跨版本的数据交流及dll注入，dll还是用c++实现，如果想用托管的dll，必须写个非托管的clr当中介调用.net dll来实现。毕竟目标程序是c/c++。   
这里要实现从系统自带的clipup.exe中调用3个函数，其中包括HwidGetCurrentEx，这个函数返回的是一个HWID结构，是微软用于认证每台机子的主要硬件标志。   
IDA分析后函数的参数大概这样。参数和函数调用约定等照抄。其他两个函数就不一一列出。
![image](https://github.com/laomms/CallExeDoNet/blob/master/01.png)   
我用vb.net实现，C#和vb.net现在已经没什么区别了，用Tangible的工具互转已经几乎达到100%，不管是整个工程还是代码互转，剩下稍微手工修改几处就可以。  
先看参数，总共6个，经过IDA调试分析，主要要得到其中的structHWID和sizeHWID，structHWID是个64位的结构体，微软没有公布这个结构体，那就拿整体来用，sizeHWID是结构体大小。  
在这里构造一个用于传递的结构体，这里的第一个参数是指定注入时调用哪个函数。其他三个子结构是三个函数的参数。  
```c
typedef struct func1
{
    char structHWID[64];
    unsigned char sizeHWID[4];
};
typedef struct func2
{
    BYTE pbData[32];
    int dwSize;
    BYTE pbDst[256];
    unsigned int sizeDst;
};
typedef struct func3
{
    char Src[1000];
    char pbData[1024];
    unsigned DataSize;
};

typedef struct  
{
    int FuncFlag;
    func1 f1;
    func2 f2;
    func3 f3;
}AgrListStruct;
#define strMapName "global_share_memory"
```
vb.net中这样定义，必须要一致，方便指针与结构体的互转。
```vb.net
    Public Structure AgrListStruct
        Public FuncFlag As Integer
        Public f1 As Func1
        Public f2 As Func2
        Public f3 As Func3
    End Structure
    Public Structure Func1
        <MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst:=64)> Public structHWID() As Byte
        Public sizeHWID As UInteger
    End Structure
    Public Structure Func2
        <MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst:=32)> Public pbData() As Byte
        Public dwSize As Integer
        <MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst:=256)> Public pbDst() As Byte
        Public sizeDst As UInteger
    End Structure
    Public Structure Func3
        <MarshalAsAttribute(UnmanagedType.ByValTStr, SizeConst:=1000)> Public Src As String
        <MarshalAsAttribute(UnmanagedType.ByValTStr, SizeConst:=1024)> Public pbData As String
        Public DataSize As UInteger
    End Structure
    Public strMapName As String = "global_share_memory"
```
dll的源码跟之前的几乎一样，只是改了调用函数的方法：
```c
BOOL Compare64(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
            return 0;
    }
    return (*szMask) == NULL;
}

DWORD64 FindPattern64(HMODULE hModule, BYTE* bMask, char* szMask)
{
    MODULEINFO moduleInfo = { 0 };
    GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO));
    //GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &moduleInfo, sizeof(MODULEINFO));
    DWORD64 dwBaseAddress = (DWORD64)moduleInfo.lpBaseOfDll;
    DWORD64 dwModuleSize = (DWORD64)moduleInfo.SizeOfImage;
    for (DWORD64 i = 0; i < dwModuleSize; i++)
    {
        if (Compare64((BYTE*)(dwBaseAddress + i), bMask, szMask))
            return (DWORD64)(dwBaseAddress + i);
    }
    return 0;
}

DWORD WINAPI MyThread(LPVOID)
{     
    AgrListStruct funcstruct;
    DWORD SharedSize = sizeof(AgrListStruct);
    //struct AgrListStruct* funcPtr = (struct AgrListStruct*)malloc(sizeof(struct AgrListStruct) + (SharedSize - 1));
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, strMapName);
    if (!hMapFile)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to open file mapping!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }

    lpBuffer = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SharedSize);
    if (!lpBuffer)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to map shared memory!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }
    memcpy(&funcstruct, lpBuffer, SharedSize);

    MODULEINFO modinfo = { 0 };
    HMODULE hModule =GetModuleHandle(NULL); // GetModuleHandle(L"clipup.exe");
    if (hModule == 0)
        return 0;   
    if (funcstruct.FuncFlag == 2)
    {
        goto func2;
    }
    else if(funcstruct.FuncFlag == 3)
    {
        goto func3;
    }

func1:
    {     
        BYTE ByteGetCurrentEx[] = "\x48\x8B\xC4\x4C\x89\x48\x20\x4C\x89\x40\x18\x89\x50\x10\x48\x89\x48\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x48";
        char MaskGetCurrentEx[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        DWORD64 pHwidGetCurrentEx = FindPattern64(hModule, ByteGetCurrentEx, MaskGetCurrentEx);
        if (pHwidGetCurrentEx == 0)
        {
            LPSTR messageBuffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
            MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
            LocalFree(messageBuffer);
            return FALSE;
        }

        typedef int(__stdcall* DelegateHwidGetCurrentEx)(unsigned __int8* , unsigned int , int**, unsigned int* , int**, unsigned int* ); //__cdecl
        DelegateHwidGetCurrentEx MyHwidGetCurrentEx = (DelegateHwidGetCurrentEx)(static_cast<long long>(pHwidGetCurrentEx));
        int* structHWID;
        unsigned int sizeHWID;

        int result = MyHwidGetCurrentEx(NULL, 0, &structHWID, &sizeHWID, 0, 0);
        if (result != 0)
        {
            char buffer[32];
            sprintf_s(buffer, "%d", result);
            MessageBoxA(NULL, buffer, "DllTitle", MB_ICONINFORMATION);
            return FALSE;
        }
        
        ::memcpy(funcstruct.f1.structHWID, structHWID, sizeof(funcstruct.f1.structHWID));
        ::memcpy(funcstruct.f1.sizeHWID, (unsigned char*)&sizeHWID, 4);
        goto MapFile;
    }
   
func2:
    {      
        BYTE ByteVRSAVaultSignPKCS[] = "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x56\x41\x57\x48\x83\xEC\x20\x4C\x8B\x74\x24\x00\x4D\x8B\xF9\x49\x8B\xD8\x8B\xFA\x48\x8B\xE9\x45\x8B\x16\x41\x8D\x72\xFE\x41\x8D\x42\xFF\x42\xC6\x04\x00\x00";
        char MaskVRSAVaultSignPKCS[] = "xxxx?xxxx?xxxx?xxxxxxxxxxxxx?xxxxxxxxxxxxxxxxxxxxxxxxxx?";
        DWORD64 pVRSAVaultSignPKCS = FindPattern64(hModule, ByteVRSAVaultSignPKCS, MaskVRSAVaultSignPKCS);
        if (pVRSAVaultSignPKCS == 0)
        {
            LPSTR messageBuffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
            MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
            LocalFree(messageBuffer);
            return FALSE;
        }
              
        typedef __int64(__fastcall* DelegateVRSAVaultSignPKCS)(const void*, int a2, int* a3, const unsigned int* a4, unsigned int* a5);
        DelegateVRSAVaultSignPKCS MyVRSAVaultSignPKCS = (DelegateVRSAVaultSignPKCS)pVRSAVaultSignPKCS;        
        unsigned int callcount = 0x100;
        int pbDST[256] = { 0 };
        unsigned int SizeDST;               

        DWORD64 result =  MyVRSAVaultSignPKCS(funcstruct.f2.pbData, funcstruct.f2.dwSize, pbDST, &SizeDST, &callcount);
        if (result != 0)
        {
            char buffer[32];
            sprintf_s(buffer, "%d", (int)result);
            MessageBoxA(NULL, buffer, "DllTitle", MB_ICONINFORMATION);
            return FALSE;
        }
        ::memcpy(funcstruct.f2.pbDst, pbDST, 256);
        funcstruct.f2.sizeDst = SizeDST;
        goto MapFile;
    }

func3:
    {
        BYTE ByteCreateGenuineTicketClient[] = "\x48\x89\x5C\x24\x00\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x85\x00\x00\x00\x00\x45\x33\xFF\x4D\x8B\xE0\x4C\x8B\xF1\x4C\x89\x7D\x98";
        char MaskCreateGenuineTicketClient[] = "xxxx?xxxxxxxxxxxxxxx????xxx????xxx????xxxxxx????xxxxxxxxxxxxx";
        DWORD64 pCreateGenuineTicketClient = FindPattern64(hModule, ByteCreateGenuineTicketClient, MaskCreateGenuineTicketClient);
        if (pCreateGenuineTicketClient == 0)
        {
            LPSTR messageBuffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
            MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
            LocalFree(messageBuffer);
            return FALSE;
        }

        typedef __int64(__fastcall* DelegateCreateGenuineTicketClient)(void* Src, __int64 a2, unsigned int* a3, unsigned __int8** a4);
        DelegateCreateGenuineTicketClient MyCreateGenuineTicketClient = (DelegateCreateGenuineTicketClient)pCreateGenuineTicketClient;
        unsigned int DataSize = 0;
        unsigned __int8* pbData;
        DWORD64 results = MyCreateGenuineTicketClient(funcstruct.f3.Src, 0xC004F012, &DataSize, &pbData);
        if (results != 0)
        {
            char buffer[32];
            sprintf_s(buffer, "%d", (int)results);
            MessageBoxA(NULL, buffer, "DllTitle", MB_ICONINFORMATION);
            return FALSE;
        }
        ::memcpy(funcstruct.f3.pbData, pbData, sizeof(funcstruct.f3.pbData));
        funcstruct.f3.DataSize = DataSize;
        goto MapFile;
    }

MapFile:
    hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SharedSize, strMapName);
    if (hMapFile == nullptr) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to create file mapping!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }
    lpMemFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == nullptr) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to map shared memory!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }

    memset(lpMemFile, 0, SharedSize);
    memcpy(lpMemFile, &funcstruct, SharedSize);
    return 0;
}
```
dll取到共享的内存后以结构体的第一个参数来区分调用的函数。各个函数各自从结构体中取相应的参数，调用结束后返回去。
主程序这边想要调用哪个函数，定义结构体第一参数为哪个
```vb.net
        Dim AgrList As New AgrListStruct()
        '第一个函数没有输入参数，只有返回参数：
         AgrList.FuncFlag = 3 = 1
        '第二个函数输入的是数组和数组大小，返回数组：
        'AgrList.FuncFlag = 3 = 2
        'AgrList.f2.pbData = New Byte() {&H27,....}
        'AgrList.f2.dwSize = 32
        '第三个函数输入的是字符串，返回的也是字符串：
        'AgrList.f3.Src = "abcd...""        
        Dim size As Integer = Marshal.SizeOf(SharedGetCurrentEx)
        Dim pnt As IntPtr = Marshal.AllocHGlobal(size)
        Marshal.StructureToPtr(SharedGetCurrentEx, pnt, False)
        Dim bytes(size - 1) As Byte
        Marshal.Copy(pnt, bytes, 0, size)
        '共享内存
        Dim ShareMemory As MemoryMappedFile = MemoryMappedFile.CreateOrOpen(strMapName, size)
        Dim stream = ShareMemory.CreateViewStream(0, size)
        Using MapView = ShareMemory.CreateViewAccessor()
            MapView.WriteArray(0, bytes, 0, bytes.Length)
        End Using
```
然后注入dll：
```vb.net
    <DllImport("kernel32.dll", EntryPoint:="CreateProcessA")>
    Public Function CreateProcess(ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As IntPtr, ByVal lpThreadAttributes As IntPtr, ByVal bInheritHandles As Boolean, ByVal dwCreationFlags As UInteger, ByVal lpEnvironment As IntPtr, ByVal lpCurrentDirectory As String, ByRef lpStartupInfo As STARTUPINFO, ByRef lpProcessInformation As PROCESS_INFORMATION) As Boolean
    End Function
    <DllImport("kernel32.dll")>
    Public Function OpenProcess(ByVal dwDesiredAccess As ProcessAccessFlags, <MarshalAs(UnmanagedType.Bool)> ByVal bInheritHandle As Boolean, ByVal dwProcessId As Integer) As IntPtr
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, CharSet:=CharSet.Ansi, ExactSpelling:=True)>
    Public Function GetProcAddress(ByVal hModule As IntPtr, ByVal procName As String) As IntPtr
    End Function
    <DllImport("kernel32.dll", CharSet:=CharSet.Unicode)>
    Public Function GetModuleHandle(ByVal lpModuleName As String) As IntPtr
    End Function
    <DllImport("kernel32.dll", SetLastError:=True, ExactSpelling:=True)>
    Public Function VirtualAllocEx(ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As IntPtr, ByVal flAllocationType As UInteger, ByVal flProtect As UInteger) As IntPtr
    End Function
    <DllImport("kernel32.dll", SetLastError:=True)>
    Public Function WriteProcessMemory(ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal lpBuffer() As Byte, ByVal nSize As Integer, ByRef lpNumberOfBytesWritten As IntPtr) As Boolean
    End Function
    <DllImport("kernel32.dll")>
    Public Function CreateRemoteThread(ByVal hProcess As IntPtr, ByVal lpThreadAttributes As IntPtr, ByVal dwStackSize As UInteger, ByVal lpStartAddress As IntPtr, ByVal lpParameter As IntPtr, ByVal dwCreationFlags As UInteger, ByVal lpThreadId As IntPtr) As IntPtr
    End Function
    <DllImport("kernel32", SetLastError:=True)>
    Function WaitForSingleObject(ByVal handle As IntPtr, ByVal milliseconds As UInt32) As UInt32
    End Function
    
```
```vb.net

        Dim FilePath = Environment.SystemDirectory & "\ClipUp.exe"
        Dim hRet = CreateProcess(FilePath, Nothing, pSecAttr, IntPtr.Zero, False, CREATE_SUSPENDED Or CREATE_NO_WINDOW, IntPtr.Zero, Nothing, si, pi)
        If hRet = False Then
            MsgBox("创建进程失败.")
            Return False
        End If
        Dim hHandle = OpenProcess(PROCESS_ALL_ACCESS Or PROCESS_VM_OPERATION Or PROCESS_VM_READ Or PROCESS_VM_WRITE, False, pi.dwProcessId)
        Dim hLoadLibrary = GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA")
        Dim pLibRemote = VirtualAllocEx(hHandle, IntPtr.Zero, DllPath.Length + 1, MEM_COMMIT, PAGE_READWRITE)
        If pLibRemote.Equals(IntPtr.Zero) Then
            MsgBox("申请目标进程空间失败.")
            Return False
        End If
        Dim bytesWritten As New IntPtr
        If WriteProcessMemory(hHandle, pLibRemote, ASCIIEncoding.ASCII.GetBytes(DllPath), DllPath.Length + 1, bytesWritten) = False Then
            MsgBox("写入内存失败!")
            Return False
        End If
        Dim dwThreadId As New IntPtr
        Dim hRemoteThread = CreateRemoteThread(hHandle, IntPtr.Zero, 0, hLoadLibrary, pLibRemote, 0, dwThreadId)
        Debug.Print("注入成功!")
        WaitForSingleObject(hRemoteThread, 500)
```
注入后，等dll执行完毕分享内存后提取共享的内存:

```vb.net
        ShareMemory = MemoryMappedFile.OpenExisting(strMapName)
        Using MapView = ShareMemory.CreateViewStream()
            Dim BytesBuffer(size - 1) As Byte
            MapView.Read(BytesBuffer, 0, size)
            Marshal.Copy(BytesBuffer, 0, pnt, size)
            AgrList = Marshal.PtrToStructure(pnt, GetType(AgrListStruct))
            Marshal.FreeHGlobal(pnt)
        End Using
```
CREATE_SUSPENDED是为了创建目标进程后马上挂起，CREATE_NO_WINDOW是为了运行目标进程时不显示窗口。  
比如第一次注入后，结构体中的structHWID已经是取到的HWID结果。  

为了测试dll调用函数有没有成功，CreateProcess目标进程后，在CreateRemoteThread之前下个断点，然后在dll的调用函数处下断点，看有没有调用成功，注意的是得附加目标进程调试，否则dll调试不了，因为已经被注入到目标进程。dll被断下：  
![image](https://github.com/laomms/CallExeDoNet/blob/master/02.png) 
主程序断下后的结果：
![image](https://github.com/laomms/CallExeDoNet/blob/master/03.png) 


