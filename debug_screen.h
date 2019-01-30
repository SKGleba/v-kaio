#pragma once

int psvDebugScreenPrintf(const char *format, ...);
int psvDebugScreenInit();
void* psvDebugScreenBase(void);

enum {
	COLOR_CYAN = 0xFFFFFF00,
	COLOR_WHITE = 0xFFFFFFFF,
	COLOR_BLACK = 0xFF000000,
	COLOR_RED = 0xFF0000FF,
	COLOR_YELLOW = 0xFF00FFFF,
	COLOR_GREY = 0xFF808080,
	COLOR_GREEN = 0xFF00FF00,
	COLOR_BLUE = 0xFFFF0000,
	COLOR_PURPLE = 0xFFFF00FF,
};
