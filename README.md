# 调用exe内部函数.net版

之前写了个c++主程序调用一个exe内部函数的例子，现在改用.net当主程序实现，主要是实现跨版本的数据交流及dll注入，dll还是用c++实现，如果想用托管的dll，必须写个非托管的clr当中介调用.net dll来实现。毕竟目标程序是c/c++。  
这里要实现从系统自带的clipup.exe中调用一个函数HwidGetCurrentEx，这个函数返回的是一个HWID结构，是微软用于认证每台机子的主要硬件标志。   
IDA分析后函数的参数大概这样，而且是个stdcall，比较好弄，先把特征码弄过来。  

我用vb.net实现，C#和vb.net现在已经没什么区别了，用Tangible的工具互转已经几乎达到100%，不管是整个工程还是代码互转，剩下稍微手工修改几处就可以。  
先看参数，总共6个，经过IDA调试分析，主要要得到其中的structHWID和sizeHWID，structHWID是个64位的结构体，微软没有公布这个结构体，那就拿整体来用，sizeHWID是结构体大小。  
在这里构造一个用于传递的结构体，这里的第一个参数是备用的，用于标志调用不同的函数，比如注入后调用的不止一个函数，就用这个来区分注入时是调用哪个函数。  
```c
struct AgrGetCurrentEx
{
    int FuncFlag = 0;
    char structHWID[64] = {0};
    unsigned char sizeHWID[4];
};
```
vb.net中这样定义:
```vb.net
    Public Structure AgrVRSAVaultSignPKCS
        Public FuncFlag As Integer
        <MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst:=32)> Public dwbyte() As Byte
        Public dwSize As UInteger
    End Structure
```


