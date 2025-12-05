![image-20251205141938656](README.assets/image-20251205141938656.png)

[下载链接](https://github.com/wqreytuk/UMHH_Release)

**驱动使用的是测试签名，需要开启测试模式，不然无法加载**

```c
bcdedit /set testsigning on
shutdown /g /t 1 /f
```

**本工具使用inline hook，因此hook点位至少需要有6字节才能进行hook**

# 基本用法

选中要hook的进程，右键选择Force Inject

![image-20251205142246528](README.assets/image-20251205142246528.png)

注入成功之后双击打开Hook引导窗口

![image-20251205142335815](README.assets/image-20251205142335815.png)

左侧为module list，右侧为hook地址输入栏和hook list

hook地址输入方式有两种：

- 先在左侧选中要hook的模块，然后在Module Offset输入框中输入hook地址在该模块的偏移量

- 在Direct Address输入框中直接输入hook地址

点击Apply Hook按钮会弹出文件选择框，选择包含你自己编写的包含[hook代码逻辑的dll](https://github.com/wqreytuk/UserModeHookHelper/tree/main/HookCodeTemplate)文件即可

在[release](https://github.com/wqreytuk/UMHH_Release)中，我们附带了两个用于演示的dll：[HookCodeTemplate.x64.dll](https://github.com/wqreytuk/UMHH_Release/blob/main/HookCodeTemplate.x64.dll)和[HookCodeTemplate.Win32.dll](https://github.com/wqreytuk/UMHH_Release/blob/main/HookCodeTemplate.Win32.dll)，分别用于X64和x86进程的hook

hook成功后会出现在hooklist列表中

![image-20251205143701823](README.assets/image-20251205143701823.png)

在hooklist中选中之后右键有四个菜单，菜单名字就是他的功能含义，不用再作解释

![image-20251205143744424](README.assets/image-20251205143744424.png)

此时我们已经hook了Notepad.exe进程的Kernelbase!CreateFileW函数，只要Notepad进行打开文件的操作，我们就能从[EtwTracer](https://github.com/wqreytuk/UMHH_Release/blob/main/EtwTracer.exe)中看到日志记录

![image-20251205144016600](README.assets/image-20251205144016600.png)
