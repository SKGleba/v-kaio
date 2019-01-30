/*
    usbmc by YifanLu
    Mod by SKGleba
*/
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/devctl.h>
#include <psp2/io/dirent.h>
#include <psp2/io/stat.h>
#include <psp2/appmgr.h>
#include <psp2/ctrl.h>
#include <psp2/power.h>
#include <psp2/registrymgr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug_screen.h"

#define KPP_INSTALL_PATH "ur0:tai/kaio.skprx"
#define KPC_INSTALL_PATH "ur0:tai/kaio.cfg"
#define GB_IN_BYTES (1073741824.0f)

#define printf psvDebugScreenPrintf

typedef struct {
    char magic[7];
    char slots[7];
} __attribute__((packed)) devsett;

const char pn[7][32] = {"LOLIcon:", "rePatch:", "reF00D:", "NoNpDrm:", "NoAvls:", "ioPlus:", "gamesd:"};
const char pd[7][128] = {"A multipurpose plugin, much like vshmenu from PSP. Currently the only OC tool available.", "Allows loading decrypted content for encrypted games. Useful for game mods.", "Secure CoProcessor bypass. Allows loading lower/higher fw modules.", "Bypass NPDRM.", "Removes the AVLS-auto-set bug.", "Allows user modules to perform I/O operations with kernel privileges.", "A sd2vita driver (sd2vita as ux0, sony mc as uma0)."};

static devsett dmeme;
int cs = 0;
int sw;

void smn(){
	psvDebugScreenClear(COLOR_BLACK);
	psvDebugScreenSetFgColor(COLOR_WHITE);
	for(int i = 0; i < 7; i++){
		if(cs==i){
			psvDebugScreenSetFgColor(COLOR_GREEN);
		}
		sw = dmeme.slots[i];
		psvDebugScreenPrintf("%s %d\n", pn[i], sw);
		psvDebugScreenSetFgColor(COLOR_WHITE);
	}
		psvDebugScreenSetFgColor(COLOR_WHITE);
	psvDebugScreenPrintf("\nDescription: %s\n\n", pd[cs]);
	printf("Options:\n\n");
	printf("  CROSS      Enable.\n");
	printf("  TRIANGLE   Disable.\n");
	printf("  CIRCLE     Exit.\n\n");
}

int _vshIoMount(int id, const char *path, int permission, void *buf);

enum {
	SCREEN_WIDTH = 960,
	SCREEN_HEIGHT = 544,
	PROGRESS_BAR_WIDTH = SCREEN_WIDTH,
	PROGRESS_BAR_HEIGHT = 10,
	LINE_SIZE = SCREEN_WIDTH,
};

static unsigned buttons[] = {
	SCE_CTRL_SELECT,
	SCE_CTRL_START,
	SCE_CTRL_UP,
	SCE_CTRL_RIGHT,
	SCE_CTRL_DOWN,
	SCE_CTRL_LEFT,
	SCE_CTRL_LTRIGGER,
	SCE_CTRL_RTRIGGER,
	SCE_CTRL_TRIANGLE,
	SCE_CTRL_CIRCLE,
	SCE_CTRL_CROSS,
	SCE_CTRL_SQUARE,
};

int vshIoMount(int id, const char *path, int permission, int a4, int a5, int a6) {
	uint32_t buf[3];

	buf[0] = a4;
	buf[1] = a5;
	buf[2] = a6;

	return _vshIoMount(id, path, permission, buf);
}

uint32_t get_key(void) {
	static unsigned prev = 0;
	SceCtrlData pad;
	while (1) {
		memset(&pad, 0, sizeof(pad));
		sceCtrlPeekBufferPositive(0, &pad, 1);
		unsigned new = prev ^ (pad.buttons & prev);
		prev = pad.buttons;
		for (size_t i = 0; i < sizeof(buttons)/sizeof(*buttons); ++i)
			if (new & buttons[i])
				return buttons[i];

		sceKernelDelayThread(1000); // 1ms
	}
}

void press_exit(void) {
	printf("\nPress any key to exit this application.\n");
	get_key();
	sceKernelExitProcess(0);
}

void press_reboot(void) {
	printf("\nPress any key to reboot.\n");
	get_key();
	scePowerRequestColdReset();
}

void press_shutdown(void) {
	printf("\nPress any key to power off.\n");
	get_key();
	scePowerRequestStandby();
}

int exists(const char *path) {
	int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
	if (fd < 0)
		return 0;
	sceIoClose(fd);
	return 1;
}

int check_safe_mode(void) {
	if (sceIoDevctl("ux0:", 0x3001, NULL, 0, NULL, 0) == 0x80010030) {
		return 1;
	} else {
		return 0;
	}
}

int copy_file(const char *dst, const char *src) {
	char buffer[0x1000];
	int ret;
	int off;
	SceIoStat stat;

	printf("Copying %s ...\n", src);

	int fd = sceIoOpen(src, SCE_O_RDONLY, 0);
	if (fd < 0) {
		printf("sceIoOpen(%s): 0x%08X\n", src, fd);
		return -1;
	}
	int wfd = sceIoOpen(dst, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
	if (wfd < 0) {
		printf("sceIoOpen(%s): 0x%08X\n", dst, wfd);
		sceIoClose(fd);
		return -1;
	}
	ret = sceIoGetstatByFd(fd, &stat);
	if (ret < 0) {
		printf("sceIoGetstatByFd: 0x%08X\n", ret);
		goto error;
	}
	ret = sceIoChstatByFd(wfd, &stat, SCE_CST_CT | SCE_CST_AT | SCE_CST_MT);
	if (ret < 0) {
		printf("sceIoChstat: 0x%08X\n", ret);
		return -1;
	}

	size_t rd, wr, total, write;
	total = 0;
	while ((rd = sceIoRead(fd, buffer, sizeof(buffer))) > 0){
		off = 0;
		while ((off += (wr = sceIoWrite(wfd, buffer+off, rd-off))) < rd){
			if (wr < 0){
				printf("sceIoWrite: 0x%08X\n", wr);
				goto error;
			}
		}
		total += rd;
	}
	if (rd < 0) {
		printf("sceIoRead: 0x%08X\n", rd);
		goto error;
	}

	sceIoClose(fd);
	sceIoClose(wfd);

	return 0;

error:
	sceIoClose(fd);
	sceIoClose(wfd);
	return -1;
}

int copy_directory(const char *dst, const char *src) {
	int fd;
	SceIoDirent dir;
	SceIoStat stat;
	char src_2[256];
	char dst_2[256];
	int ret;

	printf("Reading %s ...\n", src);

	sceIoMkdir(dst, 0777);

	if ((fd = sceIoDopen(src)) < 0) {
		printf("sceIoDopen: 0x%08X\n", fd);
	    return -1;
	}

	while ((ret = sceIoDread(fd, &dir)) > 0) {
		if (dir.d_name[0] == '\0') {
			continue;
		}
		sprintf(src_2, "%s/%s", src, dir.d_name);
		sprintf(dst_2, "%s/%s", dst, dir.d_name);
		if (SCE_S_ISDIR(dir.d_stat.st_mode)) {
			copy_directory(dst_2, src_2);
		} else {
			copy_file(dst_2, src_2);
		}
	}

	sceIoDclose(fd);
	return 0;
error:
	sceIoDclose(fd);
	return -1;
}

int find_config(const char *configpath, int remove) {
	int fd;
	int size;
	char *buffer;
	char *line;
	size_t offset, newsize;

	if ((fd = sceIoOpen(configpath, SCE_O_RDONLY, 0)) < 0) {
		return 0;
	}

	size = sceIoLseek32(fd, 0, SEEK_END);
	if (size < 0) {
		sceIoClose(fd);
		return 0;
	}
	if (sceIoLseek32(fd, 0, SEEK_SET) < 0) {
		sceIoClose(fd);
		return 0;
	}

	buffer = malloc(size);
	if (buffer == NULL) {
		sceIoClose(fd);
		return 0;
	}

	int rd, total;
	total = 0;
	while ((rd = sceIoRead(fd, buffer+total, size-total)) > 0) {
		total += rd;
	}
	sceIoClose(fd);
	if (rd < 0 || total != size) {
		free(buffer);
		return 0;
	}

	if ((line = strstr(buffer, KPP_INSTALL_PATH "\n")) == NULL) {
		free(buffer);
		return 0;
	} else {
		if (remove) {
			offset = (line - buffer);
			newsize = size - strlen(KPP_INSTALL_PATH "\n");
			memmove(line, line + strlen(KPP_INSTALL_PATH "\n"), newsize - offset);
			fd = sceIoOpen(configpath, SCE_O_TRUNC | SCE_O_CREAT | SCE_O_WRONLY, 6);
			sceIoWrite(fd, buffer, newsize);
			sceIoClose(fd);
		}
		free(buffer);
		return 1;
	}
}

int install_config(const char *path) {
	int fd;

	if (exists(path)) {
		printf("%s detected!\n", path);

		if (find_config(path, 0)) {
			printf("already installed to %s\n", path);
		} else {
			printf("installing to %s ", path);
			fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_APPEND, 0);
			sceIoWrite(fd, "\n*KERNEL\n", strlen("\n*KERNEL\n"));
			sceIoWrite(fd, KPP_INSTALL_PATH "\n", strlen(KPP_INSTALL_PATH) + 1);
			sceIoClose(fd);
			if (fd < 0) {
				printf("failed.\n");
			} else {
				printf("success.\n");
				return 0;
			}
		}
	}
	return -1;
}

int install_plugin(void) {
	printf("writing plugin...\n");
	if (copy_file(KPP_INSTALL_PATH, "app0:kplugin.skprx") < 0) {
		printf("failed.\n");
		return -1;
	} else {
		printf("success.\n");
	}

	if (install_config("ur0:tai/config.txt") < 0) {
		printf("failed install to ur0:tai/config.txt, perhaps you should upgrade HENkaku\n");
		return -1;
	}

	vshIoMount(0xD00, NULL, 2, 0, 0, 0);
	install_config("imc0:tai/config.txt");
	install_config("ux0:tai/config.txt");


	return 0;
}

int uninstall_plugin(void) {
	printf("deleting plugin... ");
	if (sceIoRemove(KPP_INSTALL_PATH) < 0) {
		printf("failed.\n");
		return -1;
	} else {
		printf("success.\n");
	}

	if (find_config("ur0:tai/config.txt", 1)) {
		printf("removed from ur0:tai/config.txt\n");
	}

	vshIoMount(0xD00, NULL, 2, 0, 0, 0);
	if (find_config("imc0:tai/config.txt", 1)) {
		printf("removed from imc0:tai/config.txt\n");
	}
	if (find_config("ux0:tai/config.txt", 1)) {
		printf("removed from ux0:tai/config.txt\n");
	}

	return 0;
}

void newcfg() {
    static devsett rmeme;
    rmeme.magic[0] = "(";
    rmeme.magic[1] = "O";
    rmeme.magic[2] = " ";
    rmeme.magic[3] = "w";
    rmeme.magic[4] = " ";
    rmeme.magic[5] = "O";
    rmeme.magic[6] = ")";
    rmeme.slots[0] = 1;
    rmeme.slots[1] = 1;
    rmeme.slots[2] = 1;
    rmeme.slots[3] = 1;
    rmeme.slots[4] = 0;
    rmeme.slots[5] = 1;
    rmeme.slots[6] = 0;
    if (exists(KPC_INSTALL_PATH)) sceIoRemove(KPC_INSTALL_PATH);
    SceUID fd;
  fd = sceIoOpen(KPC_INSTALL_PATH, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
  sceIoWrite(fd, &rmeme, sizeof(rmeme));
  sceIoClose(fd);
}

void writecfg(slot, val) {
    static devsett rmeme;
  SceUID fd;
  fd = sceIoOpen(KPC_INSTALL_PATH, SCE_O_RDONLY, 0777);
  sceIoRead(fd, &rmeme, sizeof(rmeme));
  sceIoClose(fd);
    rmeme.slots[slot] = val;
    sceIoRemove(KPC_INSTALL_PATH);
  fd = sceIoOpen(KPC_INSTALL_PATH, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
  sceIoWrite(fd, &rmeme, sizeof(rmeme));
  sceIoClose(fd);

}

int configure_plugin(void) {

  SceUID fd;
  fd = sceIoOpen("ur0:tai/kaio.cfg", SCE_O_RDONLY, 0777);
  sceIoRead(fd, &dmeme, sizeof(dmeme));
  sceIoClose(fd);
  
  loop1:
  smn();
	switch (get_key()) {
	case SCE_CTRL_CROSS:
		writecfg(cs, 1);
		goto loop1;
	case SCE_CTRL_TRIANGLE:
		writecfg(cs, 0);
		goto loop1;
	case SCE_CTRL_CIRCLE:
		break;
	case SCE_CTRL_UP:
		cs--;
		goto loop1;
	case SCE_CTRL_DOWN:
		cs++;
		goto loop1;
	default:
		goto loop1;
	}
    
  return 0;

}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	int ret = 0;

	psvDebugScreenInit();

	if (check_safe_mode()) {
		printf("Please enable HENkaku unsafe homebrew from Settings before running this installer.\n\n");
		press_exit();
	}

	printf("Options:\n\n");
	printf("  CROSS      Install the kaio plugin.\n");
    printf("  SQUARE     Configure the kaio plugin.\n");
	printf("  TRIANGLE   Uninstall the kaio plugin.\n");
	printf("  CIRCLE     Exit without doing anything.\n\n");

loop1:
	switch (get_key()) {
	case SCE_CTRL_CROSS:
	    newcfg();
		install_plugin();
		configure_plugin();
		break;
	case SCE_CTRL_SQUARE:
		configure_plugin();
		break;
	case SCE_CTRL_TRIANGLE:
		uninstall_plugin();
		break;
	case SCE_CTRL_CIRCLE:
	    press_exit();
		break;
	default:
		goto loop1;
	}

	press_exit();

	return 0;
}
