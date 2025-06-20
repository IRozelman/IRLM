TARGET = sleuth_driver.sys
SRC_DIR = ..\driver
OBJ_DIR = ..\driver\obj

WDK_INCLUDE_KM     = C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km
WDK_INCLUDE_SHARED = C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared
WDK_INCLUDE_KMCRT  = C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km\crt
WDK_LIB            = C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\km\x64
VS_MSC_INCLUDE     = C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\include

CFLAGS = /nologo /W3 /Zi /Gz /D__KERNEL__ /D_KERNEL_MODE /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /DNTDDI_WIN10_RS4 /D_WIN32_WINNT=0x0A00 /D_AMD64_ \
 /I"$(WDK_INCLUDE_KM)" \
 /I"$(WDK_INCLUDE_SHARED)" \
 /I"$(WDK_INCLUDE_KMCRT)" \
 /I"$(VS_MSC_INCLUDE)"

LFLAGS = /nologo /DEBUG /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$(TARGET) /DRIVER /LIBPATH:"$(WDK_LIB)"

LIBS = ntoskrnl.lib hal.lib

OBJS = \
 $(OBJ_DIR)\sleuth_driver.obj \
 $(OBJ_DIR)\syscall_hooks.obj \
 $(OBJ_DIR)\comms.obj \
 $(OBJ_DIR)\registery_monitor.obj

all: $(TARGET)

$(OBJ_DIR)\sleuth_driver.obj: $(SRC_DIR)\sleuth_driver.c
    cl $(CFLAGS) /c $(SRC_DIR)\sleuth_driver.c /Fo$(OBJ_DIR)\sleuth_driver.obj

$(OBJ_DIR)\syscall_hooks.obj: $(SRC_DIR)\syscall_hooks.c
    cl $(CFLAGS) /c $(SRC_DIR)\syscall_hooks.c /Fo$(OBJ_DIR)\syscall_hooks.obj

$(OBJ_DIR)\comms.obj: $(SRC_DIR)\comms.c
    cl $(CFLAGS) /c $(SRC_DIR)\comms.c /Fo$(OBJ_DIR)\comms.obj

$(OBJ_DIR)\registery_monitor.obj: $(SRC_DIR)\registery_monitor.c
    cl $(CFLAGS) /c $(SRC_DIR)\registery_monitor.c /Fo$(OBJ_DIR)\registery_monitor.obj

$(TARGET): $(OBJS)
    link $(LFLAGS) $(OBJS) $(LIBS)

clean:
    del /Q $(OBJ_DIR)\*.obj *.pdb *.sys
