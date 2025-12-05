我们的工具通过该dll的导出函数来定位hook逻辑代码位置

对于x86，我们需要导出函数HookCodeWin32

对于x64，我们需要导出函数HookCodeX64

hook逻辑代码在下面这两行注释标记之间编写即可

```
// WRITE YOUR CODE HERE
// HOOK CODE END
```

在CPU执行到hook点位之时的寄存器状态我们已经在代码开头获取了，其中`original_esp `和`original_rsp `是原始的`esp/rsp`值



如果你需要在hook代码中修改原始的寄存器的值，比如在x64下，你想修改原始的rax寄存器的值，你只需要在hook代码中编写如下代码即可：

```c
*(DWORD64*)((UCHAR*)(ULONG_PTR)rsp + 0x70) new_rax_register_value
```

