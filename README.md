# 调用exe内部函数.net版

之前写了个c++主程序调用一个exe内部函数的例子，现在改用.net当主程序实现，主要是实现跨版本的数据交流及dll注入，dll还是用c++实现，如果想用托管的dll，必须写个非托管的clr当中介调用.net dll来实现。毕竟目标程序是c/c++。  
这里要实现从系统自带的clipup.exe中调用一个函数HwidGetCurrentEx，这个函数返回的是一个HWID结构，是微软用于认证每台机子的主要硬件标志。   
IDA分析后函数的参数大概这样，而且是个stdcall，比较好弄，先把特征码弄过来。  
![image](https://github.com/laomms/CallExeDoNet/blob/master/01.png) 
我用vb.net实现，C#和vb.net现在已经没什么区别了，用Tangible的工具互转已经几乎达到100%，不管是整个工程还是代码互转，剩下稍微手工修改几处就可以。  
先看参数，总共6个，经过IDA调试分析，主要要得到其中的structHWID和sizeHWID，structHWID是个64位的结构体，微软没有公布这个结构体，那就拿整体来用，sizeHWID是结构体大小。  
在这里构造一个用于传递的结构体，这里的第一个参数是备用的，用于标志调用不同的函数，比如注入后调用的不止一个函数，就用这个来区分注入时是调用哪个函数。其他参数没什么用，不用传递，就不写进去了。  
```c
struct AgrGetCurrentEx
{
    int FuncFlag = 0;
    char structHWID[64] = {0};
    unsigned char sizeHWID[4];
};
#define strMapName "global_share_memory"
```
vb.net中这样定义:
```vb.net
    Public Structure AgrGetCurrentEx
        Public FuncFlag As Integer
        <MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst:=64)> Public structHWID() As Byte
        Public sizeHWID As UInteger
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
     
    AgrGetCurrentEx funcstruct1;
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, strMapName);
    if (!hMapFile)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to open file mapping!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }
    lpBuffer = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(funcstruct1));
    if (!lpBuffer)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to map shared memory!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }
   

    MODULEINFO modinfo = { 0 };
    HMODULE hModule = GetModuleHandleA("clipup.exe");
    if (hModule == 0)
        return 0;
   
    if (funcstruct1.FuncFlag == 2)
    {
        ::CopyMemory(&funcstruct1, (char*)lpBuffer, sizeof(funcstruct1));
        goto func2;
    }


func1:
    {   
        funcstruct1.FuncFlag = 0;
        BYTE ByteGetCurrentEx[] = "\x48\x8B\xC4\x4C\x89\x48\x20\x4C\x89\x40\x18\x89\x50\x10\x48\x89\x48\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57";
        char MaskGetCurrentEx[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
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
        ::memcpy(funcstruct1.structHWID, structHWID, sizeof(funcstruct1.structHWID));
        ::memcpy(funcstruct1.sizeHWID, (unsigned char*)&sizeHWID, 2);
        goto MapFile;
    }
   

func2:
    {
       
    }

MapFile:
    hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(funcstruct2), strMapName);
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

    memset(lpMemFile, 0, sizeof(funcstruct1));
    ::memcpy(lpMemFile, &funcstruct1, sizeof(AgrGetCurrentEx));
    return 0;
}
```
fun2是为了后续调用其他函数。
主程序先共享内存,由于这个函数没有输入参数，只有输出参数，所以没必须传其他的东西给DLL:
```vb.net
        Dim SharedGetCurrentEx As New AgrGetCurrentEx()
        SharedGetCurrentEx.FuncFlag = 1
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
        WaitForSingleObject(hRemoteThread, 2000)
```
注入后，等dll执行完毕分享内存后提取共享的内存:

```vb.net
        ShareMemory = MemoryMappedFile.OpenExisting(strMapName)
        Using MapView = ShareMemory.CreateViewStream()
            Dim BytesBuffer(size - 1) As Byte
            MapView.Read(BytesBuffer, 0, size)
            Marshal.Copy(BytesBuffer, 0, pnt, size)
            SharedGetCurrentEx = Marshal.PtrToStructure(pnt, GetType(AgrGetCurrentEx))
            Marshal.FreeHGlobal(pnt)
        End Using
```
注入后，上面的SharedGetCurrentEx结构体中的structHWID已经是取到的HWID结果。
