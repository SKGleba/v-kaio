/*
    LOLIcon, reF00D, rePatch, ioPlus by dots-tb
    NoAvls by SilicaAndPina
    NoNpDrm by TheFlow
    Gamecard-MicroSD by xyzz
    \/          \/
    Combo by SKGleba
*/

#include <taihen.h>
#include <string.h>
#include <sys/syslimits.h>
#include <stdio.h>
#include "blit.h"
#include "utils.h"


#include <psp2kern/kernel/utils.h>
#include <vitasdkkern.h>

#include <taihen.h>

#include <stdarg.h>

#define LEFT_LABEL_X CENTER(24)
#define RIGHT_LABEL_X CENTER(0)
#define printf ksceDebugPrintf
#define HOOKS_NUMBER 7
#define HOOKS_NUMBER_RF 5

#define DEVICES_AMT_RF 4

#include "repatch.h"
#include "self.h"
#include "elf.h"

static int hooks_uid[HOOKS_NUMBER];
static tai_hook_ref_t ref_hooks[HOOKS_NUMBER];

static int hook = -1;
static tai_hook_ref_t ref_hook;

static int hook_iop = -1;
static tai_hook_ref_t ref_hook_iop;

#define MOUNT_POINT_ID 0x800
#define MOUNT_POINT_ID2 0xF00

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);

typedef struct {
	const char *dev;
	const char *dev2;
	const char *blkdev;
	const char *blkdev2;
	int id;
} SceIoDevice;

typedef struct {
	int id;
	const char *dev_unix;
	int unk;
	int dev_major;
	int dev_minor;
	const char *dev_filesystem;
	int unk2;
	SceIoDevice *dev;
	int unk3;
	SceIoDevice *dev2;
	int unk4;
	int unk5;
	int unk6;
	int unk7;
} SceIoMountPoint;

typedef struct {
    char magic[7];
    char slots[7];
} __attribute__((packed)) devsett;

static SceIoDevice uma_ux0_dev = { "ux0:", "exfatux0", "sdstor0:gcd-lp-ign-entire", "sdstor0:gcd-lp-ign-entire", MOUNT_POINT_ID };
static SceIoDevice uma_uma0_dev = { "uma0:", "exfatuma0", "sdstor0:xmc-lp-ign-userext", "sdstor0:xmc-lp-ign-userext", MOUNT_POINT_ID2 };

static SceIoMountPoint *(* sceIoFindMountPoint)(int id) = NULL;

static SceIoDevice *ori_dev = NULL, *ori_dev2 = NULL;

static void io_remount(int id) {
	ksceIoUmount(id, 0, 0, 0);
	ksceIoUmount(id, 1, 0, 0);
	ksceIoMount(id, NULL, 0, 0, 0, 0);
}

static void io_mount(int id) {
	ksceIoMount(id, NULL, 0, 0, 0, 0);
}

int shellKernelRedirectUx0() {
	SceIoMountPoint *mount = sceIoFindMountPoint(MOUNT_POINT_ID);
	if (!mount) {
		return -1;
	}

	if (mount->dev != &uma_ux0_dev && mount->dev2 != &uma_ux0_dev) {
		ori_dev = mount->dev;
		ori_dev2 = mount->dev2;
	}

	mount->dev = &uma_ux0_dev;
	mount->dev2 = &uma_ux0_dev;

	return 0;
}

int shellKernelRedirectUma0() {
	SceIoMountPoint *mount = sceIoFindMountPoint(MOUNT_POINT_ID2);
	if (!mount) {
		return -1;
	}

	if (mount->dev != &uma_uma0_dev && mount->dev2 != &uma_uma0_dev) {
		ori_dev = mount->dev;
		ori_dev2 = mount->dev2;
	}

	mount->dev = &uma_uma0_dev;
	mount->dev2 = &uma_uma0_dev;

	return 0;
}

// ux0 redirect by theflow
int redirect_ux0() {
	// Get tai module info
	tai_module_info_t info;
	info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceIofilemgr", &info) < 0)
		return -1;

	// Get important function
	switch (info.module_nid) {
		case 0x9642948C: // 3.60 retail
			module_get_offset(KERNEL_PID, info.modid, 0, 0x138C1, (uintptr_t *)&sceIoFindMountPoint);
			break;

		case 0xA96ACE9D: // 3.65 retail
		case 0x3347A95F: // 3.67 retail
		case 0x90DA33DE: // 3.68 retail
			module_get_offset(KERNEL_PID, info.modid, 0, 0x182F5, (uintptr_t *)&sceIoFindMountPoint);
			break;

		default:
			return -1;
	}

	shellKernelRedirectUx0();
	io_remount(MOUNT_POINT_ID);
	shellKernelRedirectUma0();
    io_mount(MOUNT_POINT_ID2);

	return 0;
}

int poke_gamecard() {
	tai_module_info_t info;
	info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSdstor", &info) < 0)
		return -1;

	void *args = 0;
	int (*int_insert)() = 0;
	int (*int_remove)() = 0;

	module_get_offset(KERNEL_PID, info.modid, 0, 0x3BD5, (uintptr_t *)&int_insert);
	module_get_offset(KERNEL_PID, info.modid, 0, 0x3BC9, (uintptr_t *)&int_remove);

	module_get_offset(KERNEL_PID, info.modid, 1, 0x1B20 + 40 * 1, (uintptr_t *)&args);

	int_remove(0, args);
	ksceKernelDelayThread(500 * 1000);
	int_insert(0, args);
	ksceKernelDelayThread(500 * 1000);

	return 0;
}

tai_hook_ref_t hook_get_partition;
tai_hook_ref_t hook_write;
tai_hook_ref_t hook_mediaid;

uint32_t magic = 0x7FFFFFFF;

void *sdstor_mediaid;

void *my_get_partition(const char *name, size_t len) {
	void *ret = TAI_CONTINUE(void*, hook_get_partition, name, len);
	if (!ret && len == 18 && strcmp(name, "gcd-lp-act-mediaid") == 0) {
		return &magic;
	}
	return ret;
}

uint32_t my_write(uint8_t *dev, void *buf, uint32_t sector, uint32_t size) {
	if (dev[36] == 1 && sector == magic) {
		return 0;
	}
	return TAI_CONTINUE(uint32_t, hook_write, dev, buf, sector, size);
}

uint32_t my_mediaid(uint8_t *dev) {
	uint32_t ret = TAI_CONTINUE(uint32_t, hook_mediaid, dev);

	if (dev[36] == 1) {
		memset(dev + 20, 0xFF, 16);
		memset(sdstor_mediaid, 0xFF, 16);

		return magic;
	}
	return ret;
}

// allow SD cards, patch by motoharu
void patch_sdstor() {
	tai_module_info_t sdstor_info;
	sdstor_info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSdstor", &sdstor_info) < 0)
		return;

	module_get_offset(KERNEL_PID, sdstor_info.modid, 1, 0x1720, (uintptr_t *) &sdstor_mediaid);

	// patch for proc_initialize_generic_2 - so that sd card type is not ignored
	char zeroCallOnePatch[4] = {0x01, 0x20, 0x00, 0xBF};
	taiInjectDataForKernel(KERNEL_PID, sdstor_info.modid, 0, 0x2498, zeroCallOnePatch, 4); //patch (BLX) to (MOVS R0, #1 ; NOP)
	taiInjectDataForKernel(KERNEL_PID, sdstor_info.modid, 0, 0x2940, zeroCallOnePatch, 4);

	taiHookFunctionOffsetForKernel(KERNEL_PID, &hook_get_partition, sdstor_info.modid, 0, 0x142C, 1, my_get_partition);
	taiHookFunctionOffsetForKernel(KERNEL_PID, &hook_write, sdstor_info.modid, 0, 0x2C58, 1, my_write);
	taiHookFunctionOffsetForKernel(KERNEL_PID, &hook_mediaid, sdstor_info.modid, 0, 0x3D54, 1, my_mediaid);
}

// allow Memory Card remount
void patch_appmgr() {
	tai_module_info_t appmgr_info;
	appmgr_info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceAppMgr", &appmgr_info) >= 0) {
		uint32_t nop_nop_opcode = 0xBF00BF00;
		switch (appmgr_info.module_nid) {
			case 0xDBB29DB7: // 3.60 retail
			case 0x1C9879D6: // 3.65 retail
				taiInjectDataForKernel(KERNEL_PID, appmgr_info.modid, 0, 0xB338, &nop_nop_opcode, 4);
				taiInjectDataForKernel(KERNEL_PID, appmgr_info.modid, 0, 0xB368, &nop_nop_opcode, 2);
				break;

			case 0x54E2E984: // 3.67 retail
			case 0xC3C538DE: // 3.68 retail
				taiInjectDataForKernel(KERNEL_PID, appmgr_info.modid, 0, 0xB344, &nop_nop_opcode, 4);
				taiInjectDataForKernel(KERNEL_PID, appmgr_info.modid, 0, 0xB374, &nop_nop_opcode, 2);
				break;
		}
	}
}

static int sceFiosKernelOverlayResolveSyncForDriver_patched(SceUID pid, int resolveFlag, const char *pInPath, char *pOutPath, size_t maxPath) {
	int ret, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hook_iop, pid, resolveFlag, pInPath, pOutPath, maxPath);
	if(memcmp("invalid", pOutPath, sizeof("invalid") - 1) == 0)
		strncpy(pOutPath, pInPath, maxPath);
	EXIT_SYSCALL(state);
	return ret;
} 

//r1 unk pointer
//r2 unk pointer
//r3 - pointer to int (avls)
static int sceAVConfigGetVolCtrlEnable_patched(int r1, int r2, int r3, int r4) {
	int ret, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hook,r1,r2,r3,r4);
	uint32_t avls = 0;
	ksceKernelMemcpyKernelToUser((uintptr_t)r3, &avls, sizeof(avls));
	EXIT_SYSCALL(state);
	return ret;
}	

#define FAKE_AID 0x0123456789ABCDEFLL

static tai_hook_ref_t ksceKernelLaunchAppRef;
static tai_hook_ref_t ksceNpDrmGetRifInfoRef;
static tai_hook_ref_t ksceNpDrmGetRifVitaKeyRef;
static tai_hook_ref_t ksceNpDrmGetRifNameRef;
static tai_hook_ref_t ksceNpDrmGetRifNameForInstallRef;

static SceUID hooks[5];
static int n_hooks = 0;

typedef struct {
  uint16_t version;                 // 0x00
  uint16_t version_flag;            // 0x02
  uint16_t type;                    // 0x04
  uint16_t flags;                   // 0x06
  uint64_t aid;                     // 0x08
  char content_id[0x30];            // 0x10
  uint8_t key_table[0x10];          // 0x40
  uint8_t key[0x10];                // 0x50
  uint64_t start_time;              // 0x60
  uint64_t expiration_time;         // 0x68
  uint8_t ecdsa_signature[0x28];    // 0x70

  uint64_t flags2;                  // 0x98
  uint8_t key2[0x10];               // 0xA0
  uint8_t unk_B0[0x10];             // 0xB0
  uint8_t openpsid[0x10];           // 0xC0
  uint8_t unk_D0[0x10];             // 0xD0
  uint8_t cmd56_handshake[0x14];    // 0xE0
  uint32_t unk_F4;                  // 0xF4
  uint32_t unk_F8;                  // 0xF8
  uint32_t sku_flag;                // 0xFC
  uint8_t rsa_signature[0x100];     // 0x100
} SceNpDrmLicense;

int ksceNpDrmGetFixedRifName(char *rif_name, uint32_t flags, uint64_t is_gc);
int ksceNpDrmGetRifVitaKey(SceNpDrmLicense *license_buf, uint8_t *klicensee, uint32_t *flags,
                           uint32_t *sku_flag, uint64_t *start_time, uint64_t *expiration_time);

static int MakeFakeLicense(char *license_path, SceNpDrmLicense *license_buf) {
  int res;
  char path[512];
  char rif_name[48];
  uint8_t klicensee[0x10];

  // Get klicensee
  memset(klicensee, 0, sizeof(klicensee));
  res = ksceNpDrmGetRifVitaKey(license_buf, klicensee, NULL, NULL, NULL, NULL);
  if (res < 0)
    return res;

  // Check validity of klicensee
  int count = 0;

  int i;
  for (i = 0; i < sizeof(klicensee); i++) {
    if (klicensee[i] == 0)
      count++;
  }

  if (count == sizeof(klicensee))
    return -1;

  // Get fixed rif name
  res = ksceNpDrmGetFixedRifName(rif_name, 0, 0LL);
  if (res < 0)
    return res;

  // Make path
  char *p = strchr(license_path, ':');
  if (!p)
    return -2;

  snprintf(path, sizeof(path), "ux0:nonpdrm/%s/%s", p + 1, rif_name);

  // Make license structure
  SceNpDrmLicense license;
  memset(&license, 0, sizeof(SceNpDrmLicense));
  license.aid           = FAKE_AID;
  license.version       = __builtin_bswap16(1);
  license.version_flag  = __builtin_bswap16(1);
  license.type          = __builtin_bswap16(1);
  license.flags         = __builtin_bswap16(__builtin_bswap16(license_buf->flags) & ~0x400);
  license.flags2        = license_buf->flags2;

  if (__builtin_bswap32(license_buf->sku_flag) == 1 ||
      __builtin_bswap32(license_buf->sku_flag) == 3)
    license.sku_flag = __builtin_bswap32(3);
  else
    license.sku_flag = __builtin_bswap32(0);

  memcpy(license.content_id, license_buf->content_id, 0x30);
  memcpy(license.key, klicensee, 0x10);

  // Write fake license
  char *c;
  for (c = path; *c; c++) {
    if (*c == '/') {
      *c = '\0';
      ksceIoMkdir(path, 0777);
      *c = '/';
    }
  }

  SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
  if (fd < 0)
    return fd;

  ksceIoWrite(fd, &license, sizeof(SceNpDrmLicense));
  ksceIoClose(fd);

  return 0;
}

static int FindLicenses(char *path) {
  SceUID dfd = ksceIoDopen(path);
  if (dfd < 0)
    return dfd;

  int res = 0;

  do {
    SceIoDirent dir;
    memset(&dir, 0, sizeof(SceIoDirent));

    res = ksceIoDread(dfd, &dir);
    if (res > 0) {
      char new_path[512];
      snprintf(new_path, sizeof(new_path), "%s/%s", path, dir.d_name);

      if (SCE_S_ISDIR(dir.d_stat.st_mode)) {
        FindLicenses(new_path);
      } else {
        SceUID fd = ksceIoOpen(new_path, SCE_O_RDONLY, 0);
        if (fd >= 0) {
          SceNpDrmLicense license;
          int size = ksceIoRead(fd, &license, sizeof(SceNpDrmLicense));
          ksceIoClose(fd);

          if (size == sizeof(SceNpDrmLicense) && license.aid != FAKE_AID)
            MakeFakeLicense(path, &license);
        }
      }
    }
  } while (res > 0);

  ksceIoDclose(dfd);

  return 0;
}

static SceUID _ksceKernelLaunchAppPatched(void *args) {
  char *titleid  = (char *)((uintptr_t *)args)[0];
  uint32_t flags = (uint32_t)((uintptr_t *)args)[1];
  char *path     = (char *)((uintptr_t *)args)[2];
  void *unk      = (void *)((uintptr_t *)args)[3];

  char license_path[512];

  snprintf(license_path, sizeof(license_path), "ux0:license/app/%s", titleid);
  FindLicenses(license_path);

  snprintf(license_path, sizeof(license_path), "gro0:license/app/%s", titleid);
  FindLicenses(license_path);

  snprintf(license_path, sizeof(license_path), "ux0:license/addcont/%s", titleid);
  FindLicenses(license_path);

  snprintf(license_path, sizeof(license_path), "grw0:license/addcont/%s", titleid);
  FindLicenses(license_path);

  return TAI_CONTINUE(int, ksceKernelLaunchAppRef, titleid, flags, path, unk); // returns pid
}

static SceUID ksceKernelLaunchAppPatched(char *titleid, uint32_t flags, char *path, void *unk) {
  uintptr_t args[4];
  args[0] = (uintptr_t)titleid;
  args[1] = (uintptr_t)flags;
  args[2] = (uintptr_t)path;
  args[3] = (uintptr_t)unk;

  return ksceKernelRunWithStack(0x4000, _ksceKernelLaunchAppPatched, args);
}

static int ksceNpDrmGetRifInfoPatched(SceNpDrmLicense *license_buf, int license_size,
                                      int mode, char *content_id, uint64_t *aid,
                                      uint16_t *license_version, uint8_t *license_flags,
                                      uint32_t *flags, uint32_t *sku_flag,
                                      uint64_t *start_time, uint64_t *expiration_time,
                                      uint64_t *flags2) {
  int res = TAI_CONTINUE(int, ksceNpDrmGetRifInfoRef, license_buf, license_size,
                                                      mode, content_id, aid,
                                                      license_version, license_flags,
                                                      flags, sku_flag,
                                                      start_time, expiration_time,
                                                      flags2);

  // Trial version -> Full version
  if (sku_flag) {
    if (__builtin_bswap32(license_buf->sku_flag) == 1 ||
        __builtin_bswap32(license_buf->sku_flag) == 3)
      *sku_flag = 3;
    else
      *sku_flag = 0;
  }

  // Bypass expiration time for PS Plus games
  if (start_time)
    *start_time = 0LL;
  if (expiration_time)
    *expiration_time = 0x7FFFFFFFFFFFFFFFLL;

  // Get fake rif info and return success
  if (res < 0 && license_buf && license_buf->aid == FAKE_AID) {
    if (content_id)
      memcpy(content_id, license_buf->content_id, 0x30);

    if (flags) {
      if (__builtin_bswap16(license_buf->flags) & 0x200)
        (*flags) |= 0x1;
      if (__builtin_bswap16(license_buf->flags) & 0x100)
        (*flags) |= 0x10000;
      if (__builtin_bswap64(license_buf->flags2) & 0x1)
        (*flags) |= 0x2;
    }

    if (flags2)
      *flags2 = __builtin_bswap64(license_buf->flags2) & ~0x1;

    if (license_version)
      *license_version = __builtin_bswap16(license_buf->version);
    if (license_flags)
      *license_flags = (uint8_t)__builtin_bswap16(license_buf->flags);

    if (aid)
      *aid = 0LL;

    return 0;
  }

  return res;
}

static int ksceNpDrmGetRifVitaKeyPatched(SceNpDrmLicense *license_buf, uint8_t *klicensee,
                                         uint32_t *flags, uint32_t *sku_flag,
                                         uint64_t *start_time, uint64_t *expiration_time) {
  int res = TAI_CONTINUE(int, ksceNpDrmGetRifVitaKeyRef, license_buf, klicensee,
                                                         flags, sku_flag,
                                                         start_time, expiration_time);

  // Trial version -> Full version
  if (sku_flag) {
    if (__builtin_bswap32(license_buf->sku_flag) == 1 ||
        __builtin_bswap32(license_buf->sku_flag) == 3)
      *sku_flag = 3;
    else
      *sku_flag = 0;
  }

  // Bypass expiration time for PS Plus games
  if (start_time)
    *start_time = 0LL;
  if (expiration_time)
    *expiration_time = 0x7FFFFFFFFFFFFFFFLL;

  // Get fake rif info and klicensee and return success
  if (res < 0 && license_buf && license_buf->aid == FAKE_AID) {
    if (klicensee)
      memcpy(klicensee, license_buf->key, 0x10);

    if (flags) {
      if (__builtin_bswap16(license_buf->flags) & 0x200)
        (*flags) |= 0x1;
      if (__builtin_bswap16(license_buf->flags) & 0x100)
        (*flags) |= 0x10000;
      if (__builtin_bswap64(license_buf->flags2) & 0x1)
        (*flags) |= 0x2;
    }

    return 0;
  }

  return res;
}

static int ksceNpDrmGetRifNamePatched(char *rif_name, uint32_t flags, uint64_t aid) {
  int res = TAI_CONTINUE(int, ksceNpDrmGetRifNameRef, rif_name, flags, aid);

  // Allow applications on non-activated devices by using fixed rif name
  if (res < 0)
    return ksceNpDrmGetFixedRifName(rif_name, 0, 0LL);

  return res;
}

static int ksceNpDrmGetRifNameForInstallPatched(char *rif_name, SceNpDrmLicense *license_buf, uint32_t flags) {
  int res = TAI_CONTINUE(int, ksceNpDrmGetRifNameForInstallRef, rif_name, license_buf, flags);

  // Use fixed rif name for fake license
  if (license_buf && license_buf->aid == FAKE_AID)
    return ksceNpDrmGetFixedRifName(rif_name, 0, 0LL);

  return res;
}


const char *DEVICES_RF[DEVICES_AMT_RF]= {"ux0:", "ur0:", "gro0:", "grw0:"};

static int hooks_uid_rf[HOOKS_NUMBER_RF];
static tai_hook_ref_t ref_hooks_rf[HOOKS_NUMBER_RF];

#define GetExport(modname, lib_nid, func_nid, func) \
	module_get_export_func(KERNEL_PID, modname, lib_nid, func_nid, (uintptr_t *)func)
	
int (* sceSblSsMgrAESCBCDecryptForDriver)(void *src, void *dst, int size, void *key, int key_size, void *iv, int mask_enable);
void *(*sceSysmemMallocForKernel)(size_t size);
int (*sceSysmemFreeForKernel)(void *ptr);

#define REF00D_KEYS "ur0:/tai/keys.bin"

typedef struct KeyHeader {
	uint32_t magic;
	uint32_t num_of_keys;
	uint32_t key_size;
} KeyHeader;

typedef struct SceKey {
	KeyType key_type;
	SceType sce_type;
	uint8_t key_rev;
	char key[0x100];
	char iv[0x10];
	SelfType self_type;
	uint64_t minver;
	uint64_t maxver;
} SceKey;

static int current_key = 0;
static SceKey KEYS[24];

void register_key(KeyType key_type, SceType sce_type, uint16_t key_rev, char *key, char *iv, uint64_t minver, uint64_t maxver, SelfType selftype) {
	KEYS[current_key].key_type = key_type;
	KEYS[current_key].sce_type = sce_type;
	KEYS[current_key].key_rev = key_rev;
	memcpy(&KEYS[current_key].key, key, sizeof(KEYS[current_key].key));
	memcpy(&KEYS[current_key].iv, iv, sizeof(KEYS[current_key].iv));
	KEYS[current_key].minver = minver;
	KEYS[current_key].maxver = maxver;
	KEYS[current_key++].self_type = selftype;	
}

int get_key(KeyType key_type,  SceType sce_type, uint64_t sys_ver, int key_rev, SelfType selftype) {
	
	for(int i = 0; i < current_key; i++) {
		if(KEYS[i].key_type == key_type && 
			KEYS[i].sce_type == sce_type &&
			KEYS[i].self_type == selftype &&
			KEYS[i].key_rev == key_rev &&
			sys_ver >= KEYS[i].minver &&
			sys_ver <= KEYS[i].maxver)
				return i;
	}
	return -1;
}


static ModuleMetadataDecKeyInfo_t MetadataDecKeyInfo;
static ModuleMetadataHeader_t MetadataHeader;
static ModuleMetadataKeyInfo_t MetadataKeyInfo[5];
static ModuleSectionOffsetInfo_t SectionOffsetInfo[5];
static SceSelfAuthInfo self_auth;

static int doDecrypt = 0, currentKey = 0, currentSeg = 0;
static SceAesContext scectx;

static int decrypt_module(char *header, int header_size, SceSblSmCommContext130 *context_130, char *path_buf_aligned, char *read_buf_aligned) {
	int ret;

	char iv[0x10];
	memset(&iv, 0, sizeof(iv));

	SCE_header *shdr = (SCE_header *)header;
	SCE_appinfo *appinfo = (SCE_appinfo *)(header + shdr->appinfo_offset);
	segment_info *seg_info = (segment_info *)(header + shdr->section_info_offset);
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(header + shdr->elf_offset);

	int i = 0;
	while(i < ehdr->e_phnum && seg_info[i].encryption != 1) 
		i++;
	
	if(i == ehdr->e_phnum)
		return -1;

	int offset = shdr->metadata_offset + 0x30;
	char *meta_data_buf = header + offset;
	offset += 0x40;
	uint64_t sysver = -1;
	PSVita_CONTROL_INFO *control_info = (PSVita_CONTROL_INFO *)(header + shdr->controlinfo_offset);
	while(control_info->next) {
		switch(control_info->type) {
			case 4:
				sysver = control_info->PSVita_elf_digest_info.min_required_fw;
				sysver = sysver << 32;
				break;
		}
		control_info = (PSVita_CONTROL_INFO*)((char*)control_info + control_info->size);
	}
	if(sysver<=0) 
		sysver = appinfo->version;

	if(appinfo->self_type == APP) {
		char klicensee_dec[0x10];
		int keytype = shdr->sdk_type >= 2 ? 1 : 0;
		
		int np_key_index = get_key(NPDRM, shdr->header_type, sysver, keytype, appinfo->self_type);
		if(np_key_index < 0)
			return np_key_index;	
		
		memset(&iv, 0, sizeof(iv) );
		ret = sceSblSsMgrAESCBCDecryptForDriver(&(context_130->self_auth_info.klicensee), &klicensee_dec, 0x10, &(KEYS[np_key_index].key), 0x80, &iv, 1);
		if(ret < 0)
			return ret;
		
		memset(&iv, 0, sizeof(iv) );
		ret = sceSblSsMgrAESCBCDecryptForDriver(meta_data_buf, read_buf_aligned, 0x40, klicensee_dec, 0x80, &iv, 1);
		if(ret < 0)
			return ret;

		meta_data_buf = read_buf_aligned;
	}
	
	memset(&iv, 0, sizeof(iv) );
	
	int key_index = get_key(METADATA, shdr->header_type, sysver, shdr->sdk_type, appinfo->self_type);
	if(key_index < 0)
		return key_index;
	memcpy(&iv, &(KEYS[key_index].iv), 0x10);
	
	ret = sceSblSsMgrAESCBCDecryptForDriver(meta_data_buf, &MetadataDecKeyInfo, 0x40, &(KEYS[key_index].key), 0x100, &iv, 1);
	if(ret < 0)
		return ret;
	
	#define DecryptMetadata(src, len, dst, add) \
		sceSblSsMgrAESCBCDecryptForDriver(src,  dst, len, &MetadataDecKeyInfo.key, 0x80, &MetadataDecKeyInfo.iv, 1); \
		offset += add ? len : 0
		
	DecryptMetadata(header + offset, sizeof(ModuleMetadataHeader_t), &MetadataHeader, 1);
	if(MetadataHeader.sig_type != 5)
		return -1;

	DecryptMetadata(header + offset, (sizeof(ModuleSectionOffsetInfo_t) * MetadataHeader.section_num), &SectionOffsetInfo, 1);
	DecryptMetadata(header + offset,  sizeof(ModuleMetadataKeyInfo_t) * MetadataHeader.section_num, &MetadataKeyInfo, 1);

	char *meta_buf = NULL, *meta_buf_aligned;
	if(header_size - offset > 0x1000)
		return -1;
	meta_buf = sceSysmemMallocForKernel(header_size - offset + 63);
	meta_buf_aligned = (char *)(((int)meta_buf + 63) & 0xFFFFFFC0);

	DecryptMetadata(header + offset,   header_size - offset , meta_buf_aligned, 0);
	
	PSVITA_METADATA_INFO *meta_info = (PSVITA_METADATA_INFO *)meta_buf_aligned;
	while(offset < header_size) {
		switch(meta_info->type) {
			case 1:
				memcpy(&self_auth.capability, &meta_info->PSVITA_caps_info.capability, sizeof(self_auth.capability));
				break;
			case 3:
				memcpy(&self_auth.attribute, &meta_info->PSVITA_attrs_info.attribute, sizeof(self_auth.attribute));
				break;
		}
		if(meta_info->next) {
			offset += meta_info->size;
			meta_info = (PSVITA_METADATA_INFO*)((char*)meta_info + meta_info->size);
		} else
			break;
	}
	
	sceSysmemFreeForKernel(meta_buf);
	
	self_auth.program_authority_id = context_130->self_auth_info.program_authority_id;
	doDecrypt = 1;
	currentSeg = 0;
	
	Elf32_Phdr *phdr = (Elf32_Phdr *)(header + shdr->phdr_offset);
	for(int i = 0; i < MetadataHeader.section_num; i++) {
		if(SectionOffsetInfo[i].section_idx==currentSeg) 
			currentKey = i;
		if(phdr[SectionOffsetInfo[i].section_idx].p_type == 0x6fffff01)
			SectionOffsetInfo[i].section_size = 0;
	}
	
	memset(&scectx, 0, sizeof(scectx));
	ksceAesInit1(&scectx, 0x80, 0x80, &MetadataKeyInfo[currentKey].key);

	return 0;
}

static int ksceSblAuthMgrAuthHeaderForKernel_patched_rf(int ctx, char *header, int header_size, SceSblSmCommContext130 *context_130){
	int ret = -1, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks_rf[3], ctx, header, header_size, context_130);
	doDecrypt = 0;
	if(ret < 0) {
		
		char *path_buf = NULL, *path_buf_aligned;
		path_buf = sceSysmemMallocForKernel(1024 + 63);
		path_buf_aligned = (char *)(((int)path_buf + 63) & 0xFFFFFFC0);		
		
		char *read_buf = NULL, *read_buf_aligned;
		read_buf = sceSysmemMallocForKernel(0x40 + 63);
		read_buf_aligned = (char *)(((int)read_buf + 63) & 0xFFFFFFC0);
		
		decrypt_module(header, header_size, context_130, path_buf_aligned, read_buf_aligned);
		
		sceSysmemFreeForKernel(path_buf);
		sceSysmemFreeForKernel(read_buf);
	}

	SCE_header *shdr = (SCE_header *)header;
	SCE_appinfo *appinfo = (SCE_appinfo *)(header + shdr->appinfo_offset);	
	if(context_130->self_auth_info_caller.program_authority_id  == self_auth.program_authority_id || appinfo->authid   == self_auth.program_authority_id) 
		memcpy((char*)(context_130->self_auth_info.capability), (char*)&self_auth + 0x10, 0x40);
	
	EXIT_SYSCALL(state);
	return ret;
}

void aes_128_ctr_decrypt_seg(uint8_t *src, int length){
	uint8_t buffer[0x10];
	uint8_t buffer_enc[0x10];
	unsigned i;
	int bi;
	for (i = 0, bi = 0x10; i < length; ++i, ++bi) {
		if (bi == 0x10) {/* we need to regen xor compliment in buffer */

			memcpy(buffer, &MetadataKeyInfo[currentKey].iv, 0x10);
			ksceAesEncrypt1(&scectx, &buffer, &buffer_enc);
			memcpy(buffer, buffer_enc, 0x10);
			/* Increment Iv and handle overflow */
			for (bi = (0x10 - 1); bi >= 0; --bi) {
				/* inc will owerflow */
				if (MetadataKeyInfo[currentKey].iv[bi] == 255) {
					MetadataKeyInfo[currentKey].iv[bi] = 0;
					continue;
				} 
				MetadataKeyInfo[currentKey].iv[bi] += 1;
				break;
			}
			bi = 0;
		}
		src[i] = (src[i] ^ buffer[bi]);
	}
}

static int decrypt_buffer_patched(int ctx, void *buffer, size_t len) {
	int ret, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks_rf[1], ctx, buffer, len);

	if(doDecrypt && ret < 0) {
		while(SectionOffsetInfo[currentKey].section_size <=0 && currentKey < MetadataHeader.section_num) {
			currentSeg++;
			for(int i = 0; i < MetadataHeader.section_num; i++) {
				if(SectionOffsetInfo[i].section_idx==currentSeg) 
					currentKey = i;
				
			}
			memset(&scectx, 0, sizeof(scectx));
			ksceAesInit1(&scectx, 0x80, 0x80, &MetadataKeyInfo[currentKey].key);
			
		}
		if(currentKey < MetadataHeader.section_num) {
			aes_128_ctr_decrypt_seg(buffer, len);
			SectionOffsetInfo[currentKey].section_size -= len;
			ret = 0;
		}
	}
	EXIT_SYSCALL(state);
	return ret;
}

static int ksceIoOpen_patched_rf(const char *filename, int flag, SceIoMode mode) {
	int ret = -1, state;
	ENTER_SYSCALL(state);
	
	if((flag & SCE_O_WRONLY) != SCE_O_WRONLY && hooks_uid_rf[3] <= 0 && strstr(filename, "henkaku.suprx") != NULL)
				hooks_uid_rf[3] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks_rf[3], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0xF3411881, ksceSblAuthMgrAuthHeaderForKernel_patched_rf);
	
	if(ret <= 0) ret = TAI_CONTINUE(int, ref_hooks_rf[0], filename, flag, mode);
	EXIT_SYSCALL(state);
	return ret;
}

static mount_point_overlay addcont_overlay;
static mount_point_overlay repatch_overlay;

int (*_sceFiosKernelOverlayRemoveForProcessForDriver)(SceUID pid, uint32_t id);

int checkFile(const char *filename) {
	SceIoStat k_stat;
	return !ksceIoGetstat(filename, &k_stat);
}

void stripDevice(const char *inPath, char *outPath) {
	char *old_path_file =  strchr(inPath, ':') + 1;
	old_path_file = (old_path_file[0] == '/') ? strchr(old_path_file + 1, '/') + 1 : strchr(old_path_file, '/') + 1;
	snprintf(outPath, PATH_MAX, rePatchFolder"/%s", old_path_file);
}

static char temp_path[PATH_MAX];
static int resolveFolder(char *filepath) {
	for(int i = 0; i < DEVICES_AMT; i++) {
		snprintf(temp_path, sizeof(temp_path), "%s/%s", DEVICES[i], filepath);
		if(checkFile(temp_path))
			return (strncpy(filepath, temp_path, 292) != NULL);
	}
	return checkFile(filepath);
}

static char manu_patch[PATH_MAX];
static int overlayHandler(uint32_t pid, mount_point_overlay *overlay_old, mount_point_overlay *overlay_new, int opt) {
	if(overlay_new->PID == pid && overlay_new->mountId > 0)
		_sceFiosKernelOverlayRemoveForProcessForDriver(pid, overlay_new->mountId);
	overlay_new->mountId = 0;
	overlay_new->PID = pid;
	overlay_new->order = 0x85;
	overlay_new->type = 1;
	if(opt & AIDS_PATH)
		strncpy(overlay_new->dst, "addcont0:", sizeof(overlay_new->dst));
	else
		strncpy(overlay_new->dst, overlay_old->src, sizeof(overlay_new->dst));
	char titleid[32];
	if(ksceKernelGetProcessTitleId(pid, titleid, sizeof(titleid))==0) {
		if(opt & APP_PATH)
			snprintf(overlay_new->src, sizeof(overlay_new->src), rePatchFolder"/%s", titleid);
		else if((opt & DLC_PATH) || (opt & AIDS_PATH))
			snprintf(overlay_new->src, sizeof(overlay_new->src), addcontFolder"/%s", titleid);
		else if((opt & MANU_PATH) && (strncmp("NPXS10027", titleid, sizeof("NPXS10027"))==0 || strncmp("main", titleid, sizeof("main"))==0)) 
			strncpy(overlay_new->src, manu_patch, sizeof(manu_patch));
	}
	int ret = resolveFolder(overlay_new->src);
	overlay_new->dst_len = strnlen(overlay_new->dst, sizeof(overlay_new->dst));
	overlay_new->src_len = strnlen(overlay_new->src, sizeof(overlay_new->src));
	return ret;
}

static int sceFiosKernelOverlayAddForProcessForDriver_patched(uint32_t pid, mount_point_overlay *overlay, uint32_t *outID) {
	int ret = -1, state;
	uint32_t repatch_outID =0;
	ENTER_SYSCALL(state);
	if(ksceSblACMgrIsGameProgram(pid)) {
		if(strncmp(overlay->dst, "app0:", sizeof("app0:")) == 0) {
			if(overlayHandler(pid, overlay, &repatch_overlay, APP_PATH))
			repatch_overlay.mountId = TAI_CONTINUE(int, ref_hooks[0], pid, &repatch_overlay, &repatch_outID);
				repatch_overlay.mountId =  repatch_outID;
			repatch_outID = 0;
			if(overlayHandler(pid, NULL, &addcont_overlay, AIDS_PATH))
				addcont_overlay.mountId =  TAI_CONTINUE(int, ref_hooks[0], pid, &addcont_overlay, &repatch_outID);
			addcont_overlay.mountId = repatch_outID;
		} else if(strncmp(overlay->dst, "addcont0:", sizeof("addcont0:")) == 0 && overlayHandler(pid, overlay, &addcont_overlay, DLC_PATH)) {
			addcont_overlay.mountId = TAI_CONTINUE(int, ref_hooks[0], pid, &addcont_overlay, &repatch_outID);
			addcont_overlay.mountId =  repatch_outID;
		}
	}				
	if(strncmp(overlay->dst, repatch_overlay.dst, sizeof(repatch_overlay.dst)) == 0 && overlayHandler(pid, overlay, &repatch_overlay, PATCH_PATH)) {
			repatch_overlay.mountId = TAI_CONTINUE(int, ref_hooks[0], pid, &repatch_overlay, &repatch_outID);
			repatch_overlay.mountId =  repatch_outID;	
	} else if(strncmp("gp", overlay->dst, sizeof("gp") - 1) == 0 && overlayHandler(pid, overlay, &repatch_overlay, MANU_PATH)) {
		TAI_CONTINUE(int, ref_hooks[0], pid, &repatch_overlay, &repatch_outID);
		repatch_overlay.mountId =  repatch_outID;
	}
	ret = TAI_CONTINUE(int, ref_hooks[0], pid, overlay, outID);
	EXIT_SYSCALL(state);
	return ret;
}

static char repatch_path[PATH_MAX];
static SceSelfAuthInfo self_auth_info;

static int ksceSblAuthMgrAuthHeaderForKernel_patched(int ctx, char *header, int header_size, SceSblSmCommContext130 *context_130){
	int ret = -1, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks[6], ctx, header, header_size, context_130);
	SCE_header *shdr = (SCE_header *)header;
	SCE_appinfo *appinfo = (SCE_appinfo *)(header + shdr->appinfo_offset);
	if(context_130->self_auth_info_caller.program_authority_id  == self_auth_info.program_authority_id || appinfo->authid == self_auth_info.program_authority_id) {
		memcpy((char*)(context_130->self_auth_info.capability), (char*)&self_auth_info + 0x10, 0x40);
	}
	EXIT_SYSCALL(state);
	return ret;
}
static char eboot_path[PATH_MAX];
static int ksceIoOpen_patched(const char *filename, int flag, SceIoMode mode) {
	int ret = -1, state;
	ENTER_SYSCALL(state);
	if ((flag & SCE_O_WRONLY) != SCE_O_WRONLY && ksceSblACMgrIsShell(0) && (strncmp(filename, "ux0:", sizeof("ux0:") -1) == 0) && strstr(filename, "/eboot.bin") != NULL){
			stripDevice(filename, eboot_path);
			resolveFolder(eboot_path);
			if((ret = TAI_CONTINUE(int, ref_hooks[1], eboot_path, flag, mode))>0) {
				strncpy(repatch_path, eboot_path, sizeof(repatch_path));
				char *end_path = strstr(repatch_path, "eboot.bin");
				*end_path = 0;
				snprintf(eboot_path, PATH_MAX, "%sself_auth.bin", repatch_path);
				SceUID fd = ksceIoOpen(eboot_path, SCE_O_RDONLY, 0);
				if (fd >= 0) {
					if (ksceIoRead(fd, &self_auth_info, 0x90) != 0x90)
						memset(&self_auth_info, 0, sizeof(self_auth_info));
					ksceIoClose(fd);
				}
				if (hooks_uid[6] <= 0)
					hooks_uid[6] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks[6], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0xF3411881, ksceSblAuthMgrAuthHeaderForKernel_patched);
			}		
	}
	if(ret <= 0) ret = TAI_CONTINUE(int, ref_hooks[1], filename, flag, mode);
	EXIT_SYSCALL(state);
	return ret;
}

static int confirmDlc(char *filepath, const char *adcont_id) {
	snprintf(filepath, PATH_MAX, "%s/%s", addcont_overlay.src, adcont_id);
	return checkFile(filepath);
}

static char dlc_path[PATH_MAX];
static int sceAppMgrDrmOpenForDriver_patched(drm_opts *drmOpt, int r2) {
	int ret = -1, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks[2], drmOpt, r2);
	if(ret < 0 && !ksceSblACMgrIsShell(0)) 
		ret = confirmDlc(dlc_path, drmOpt->adcont_id) ? 0 : ret;
	EXIT_SYSCALL(state);
	return ret;
}

static char dlc_path2[PATH_MAX];
static int sceAppMgrDrmCloseForDriver_patched(drm_opts *drmOpt, int r2) {
	int ret = -1, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks[3], drmOpt, r2);
	if(ret < 0 && !ksceSblACMgrIsShell(0))
		ret = confirmDlc(dlc_path2, drmOpt->adcont_id) ? 0 : ret;
	EXIT_SYSCALL(state);
	return ret;
}

static int io_item_thing_patched(io_scheduler_item *item, int r1) {
	int ret, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks[5], item, r1);
	if(ret == 0x80010013 &&item->unk_10 == 0x800) 
		item->unk_10 = 1;
	EXIT_SYSCALL(state);
	return ret;
}

static int ksceAppMgrGameDataMount_patched(char *input, int r2, int r3, char *outpath) {
	int ret = -1, state;
	ENTER_SYSCALL(state);
	stripDevice(input, manu_patch);
	ret = TAI_CONTINUE(int, ref_hooks[4], input, r2, r3, outpath);
	EXIT_SYSCALL(state);
	return ret;
}

static SceUID g_hooks[14];

static const char *ERRORS[5]={ 
	#define NO_ERROR 0
	"No error.", 
	#define SAVE_ERROR 1
	"There was a problem saving.", 
	#define SAVE_GOOD 2
	"Configuration saved.", 
	#define LOAD_ERROR 3
	"There was a problem loading.", 
	#define LOAD_GOOD 4
	"Configuration loaded."
};

int error_code = NO_ERROR;

#define CONFIG_PATH "ur0:LOLIcon/"

typedef struct titleid_config {
	int mode;
	int hideErrors;
	int showBat;
	int buttonSwap;
	int showFPS;
} titleid_config;

static char config_path[PATH_MAX];
static titleid_config current_config;

static char titleid[32];
uint32_t current_pid = 0, shell_pid = 0;

int showMenu = 0, pos = 0, isReseting = 0, forceReset = 0, isPspEmu = 0, isShell = 1;
int page = 0;
int willexit = 0;
static uint64_t ctrl_timestamp, msg_time = 0;

uint32_t *clock_speed;
unsigned int *clock_r1;
unsigned int *clock_r2;	

#define TIMER_SECOND         1000000 // 1 second
int fps;
long curTime = 0, lateTime = 0, fps_count = 0;

static int profile_default[] = {266, 166, 166, 111, 166};
static int profile_game[] = {444, 222, 222, 166, 222};
static int profile_max_performance[] = {444, 222, 222, 166, 333};
static int profile_holy_shit_performance[] = {500, 222, 222, 166, 333};
static int profile_max_battery[] = {111, 111, 111, 111, 111};
static int* profiles[5] = {profile_default,profile_game,profile_max_performance, profile_holy_shit_performance, profile_max_battery};


int (*_kscePowerGetGpuEs4ClockFrequency)(int*, int*);
int (*_kscePowerSetGpuEs4ClockFrequency)(int, int);
int (*_kscePowerGetGpuClockFrequency)(void);
int (*_kscePowerSetGpuClockFrequency)(int);
int (*_ksceKernelGetModuleInfo)(SceUID, SceUID, SceKernelModuleInfo *);
int (*_ksceKernelGetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
int (*_ksceKernelExitProcess)(int);

#define ksceKernelExitProcess _ksceKernelExitProcess
#define ksceKernelGetModuleInfo _ksceKernelGetModuleInfo
#define ksceKernelGetModuleList _ksceKernelGetModuleList
#define kscePowerGetGpuEs4ClockFrequency _kscePowerGetGpuEs4ClockFrequency
#define kscePowerSetGpuEs4ClockFrequency _kscePowerSetGpuEs4ClockFrequency
#define kscePowerGetGpuClockFrequency _kscePowerGetGpuClockFrequency
#define kscePowerSetGpuClockFrequency _kscePowerSetGpuClockFrequency

void reset_config() {
	memset(&current_config, 0, sizeof(current_config));
}

int load_config() {
	snprintf(config_path, sizeof(config_path), CONFIG_PATH"%s/config.bin", titleid);
	printf("loaded %s\n", config_path);
	if(ReadFile(config_path, &current_config, sizeof(current_config))<0) {
		snprintf(config_path, sizeof(config_path), CONFIG_PATH"default.bin");
		if(ReadFile(config_path, &current_config, sizeof(current_config))<0) {
			reset_config();
			return -1;
		}
	}
	return 0;
}

int save_config() {
	snprintf(config_path, sizeof(config_path), CONFIG_PATH"%s", titleid);
	ksceIoMkdir(config_path, 6);
	snprintf(config_path, sizeof(config_path), CONFIG_PATH"%s/config.bin", titleid);
	if(WriteFile(config_path, &current_config, sizeof(current_config))<0)
		return -1;
	return 0;	
}

int save_default_config() {
	snprintf(config_path, sizeof(config_path), CONFIG_PATH"default.bin");
	if(WriteFile(config_path, &current_config, sizeof(current_config))<0)
		return -1;
	return 0;	
}

void refreshClocks() {
	isReseting = 1;
	kscePowerSetArmClockFrequency(profiles[current_config.mode][0]);
	kscePowerSetBusClockFrequency(profiles[current_config.mode][1]);
	kscePowerSetGpuEs4ClockFrequency(profiles[current_config.mode][2], profiles[current_config.mode][2]);
	kscePowerSetGpuXbarClockFrequency(profiles[current_config.mode][3]);
	kscePowerSetGpuClockFrequency(profiles[current_config.mode][4]);
	isReseting = 0;
}

void load_and_refresh() {
	error_code = LOAD_GOOD;
	if(load_config()<0) 
		error_code = LOAD_ERROR;			
	refreshClocks();
	printf("forcing reset\n");
}


// This function is from VitaJelly by DrakonPL and Rinne's framecounter
void doFps() {
	fps_count++;
	if ((curTime - lateTime) > TIMER_SECOND) {
		lateTime = curTime;
		fps = (int)fps_count;
		fps_count = 0;
	}
	blit_stringf(20, 15, "%d",  fps);
}

void drawErrors() {
	if(error_code > 0) {
		if(!curTime || (msg_time == 0 && !showMenu))
			msg_time = (curTime = ksceKernelGetProcessTimeWideCore()) + TIMER_SECOND * 2;
		if((!current_config.hideErrors && curTime < msg_time) || showMenu)
			blit_stringf(20, 0, "%s : %d",  ERRORS[error_code], error_code);
	}
}

int kscePowerSetClockFrequency_patched(tai_hook_ref_t ref_hook, int port, int freq){
	int ret = 0;
	if(!isReseting)
		profile_default[port] = freq;
	if(port==0) {
		if(freq == 500) {
			ret = TAI_CONTINUE(int, ref_hook, 444);
			ksceKernelDelayThread(10000);
			*clock_speed = profiles[current_config.mode][port];
			*clock_r1 = 0xF;
			*clock_r2 = 0x0;
			return ret;
		}
	} 
	if(port==2) {
		ret = TAI_CONTINUE(int, ref_hook, profiles[current_config.mode][port], profiles[current_config.mode][port]);
	} else
		ret = TAI_CONTINUE(int, ref_hook, profiles[current_config.mode][port]);
	return ret;
}

static tai_hook_ref_t power_hook1;
static int power_patched1(int freq) {
	return kscePowerSetClockFrequency_patched(power_hook1,0,freq);
}

static tai_hook_ref_t power_hook2;
static int power_patched2(int freq) {
	return kscePowerSetClockFrequency_patched(power_hook2,1,freq);
}

static tai_hook_ref_t power_hook3;
static int power_patched3(int freq) {
	return kscePowerSetClockFrequency_patched(power_hook3,2,freq);
}

static tai_hook_ref_t power_hook4;
static int power_patched4(int freq) {
	return kscePowerSetClockFrequency_patched(power_hook4,3,freq);
}

int checkButtons(int port, tai_hook_ref_t ref_hook, SceCtrlData *ctrl, int count) {
	int ret = 0, state;
	if (ref_hook == 0)
		ret = 1;
	else {
		ret = TAI_CONTINUE(int, ref_hook, port, ctrl, count);
		if(!showMenu){
			if (!isPspEmu && (ctrl->buttons & SCE_CTRL_UP)&&(ctrl->buttons & SCE_CTRL_SELECT))
				ctrl_timestamp = showMenu = 1;
			if (current_config.buttonSwap && 
				((isShell && shell_pid == ksceKernelGetProcessId())||(!isShell && current_pid == ksceKernelGetProcessId())) && 
				(ctrl->buttons & 0x6000) && ((ctrl->buttons & 0x6000) != 0x6000))
					ctrl->buttons = ctrl->buttons ^ 0x6000;
		} else {
			unsigned int buttons = ctrl->buttons;
			ctrl->buttons = 0;
			if(ctrl->timeStamp > ctrl_timestamp + 300*1000) {
				if( ksceKernelGetProcessId() == shell_pid) {
					if (buttons & SCE_CTRL_LEFT){
						switch(page) {
							case 1:
								if(current_config.mode > 0) {
									ctrl_timestamp = ctrl->timeStamp;
									current_config.mode--;
									refreshClocks();
								}
								break;
						}
					} else if ((buttons & SCE_CTRL_RIGHT)){
						switch(page) {
							case 1:
								if(current_config.mode <4) {
									ctrl_timestamp = ctrl->timeStamp;
									current_config.mode++;
									refreshClocks();
								}
								break;
						}
					} else if((buttons & SCE_CTRL_UP) && pos > 0) {
						ctrl_timestamp = ctrl->timeStamp;
						pos--;
					} else if (buttons & SCE_CTRL_CIRCLE)
						page = pos = 0;
					 else if (buttons & SCE_CTRL_CROSS) {
						 switch(page) {
							case 0:
								switch(pos) {
									case 0:
										error_code = SAVE_GOOD;
										if(save_config() < 0)
											error_code = SAVE_ERROR;
										break;
									case 1: {
										error_code = SAVE_GOOD;
										if(save_default_config() < 0)
											error_code = SAVE_ERROR;
										}
										break;
									case 2:
										reset_config();
										refreshClocks();
										break;
									case 3:
										page = 1;
										pos = 0;
										break;
									case 4:
										page = 2;
										pos = 0;
										break;
									case 5:
										page = 3;
										pos = 0;
										break;
									case 6:
										willexit = current_pid;
										break;
									case 7:
										kscePowerRequestSuspend();
										break;
									case 8:
										kscePowerRequestColdReset();
										break;
									case 9:
										kscePowerRequestStandby();
										break;
								}
								break;
							case 2:
								switch(pos) {
									case 0:
										current_config.showFPS = !current_config.showFPS;
										break;
									case 1:
										current_config.showBat = !current_config.showBat;
										break;		
									case 2:
										current_config.hideErrors = !current_config.hideErrors;
										break;
	
								}
								break;
							case 3:
								switch(pos) {
									case 0:
										current_config.buttonSwap = !current_config.buttonSwap;
										break;
								}
								break;								
						 }
						 ctrl_timestamp = ctrl->timeStamp;
					 }  else if (buttons & SCE_CTRL_DOWN) {
						pos++;
						ctrl_timestamp = ctrl->timeStamp;
					}
				}
				if((buttons & SCE_CTRL_SELECT)&&(buttons & SCE_CTRL_DOWN))
					error_code = showMenu = 0;
			}
		}
		if(KERNEL_PID!=ksceKernelGetProcessId()&& shell_pid!=ksceKernelGetProcessId()) {
			if(forceReset == 1) {
				if(current_pid==ksceKernelGetProcessId()) {
					if(ksceKernelGetProcessTitleId(current_pid, titleid, sizeof(titleid))==0 && titleid[0] != 0) 
						forceReset = 2;
				} else 
					current_pid=ksceKernelGetProcessId();
			}
			if(willexit == current_pid && current_pid == ksceKernelGetProcessId()) 
				ksceKernelExitProcess(0);
			else
				willexit = 0;
		} else if(forceReset == 2) {
			isShell = 0;
			load_and_refresh();
			msg_time = curTime = fps_count = lateTime = forceReset = 0;
		}
	}
	return ret;
}

static tai_hook_ref_t ref_hook1;
static int keys_patched1(int port, SceCtrlData *ctrl, int count) {
	int ret, state;
	if(isPspEmu) {
		ENTER_SYSCALL(state);
		ret = TAI_CONTINUE(int, ref_hook1, port, ctrl, count);
		EXIT_SYSCALL(state);
	} else 
		ret = checkButtons(port, ref_hook1, ctrl, count);
	return ret;
}   

static tai_hook_ref_t ref_hook2;
static int keys_patched2(int port, SceCtrlData *ctrl, int count) {
	return checkButtons(port, ref_hook2, ctrl, count);
}   

static tai_hook_ref_t ref_hook3;
static int keys_patched3(int port, SceCtrlData *ctrl, int count) {
	return checkButtons(port, ref_hook3, ctrl, count);
}  

static tai_hook_ref_t ref_hook4;
static int keys_patched4(int port, SceCtrlData *ctrl, int count) {
	return checkButtons(port, ref_hook4, ctrl, count);
}    

static tai_hook_ref_t ref_hook5;
static int keys_patched5(int port, SceCtrlData *ctrl, int count) {
	return checkButtons(port, ref_hook5, ctrl, count);
}    

static tai_hook_ref_t ref_hook6;
static int keys_patched6(int port, SceCtrlData *ctrl, int count) {
	return checkButtons(port, ref_hook6, ctrl, count);
}    

static tai_hook_ref_t ref_hook7;
static int keys_patched7(int port, SceCtrlData *ctrl, int count) {
	return checkButtons(port, ref_hook7, ctrl, count);
}    

static tai_hook_ref_t ref_hook8;
static int keys_patched8(int port, SceCtrlData *ctrl, int count) {
	return checkButtons(port, ref_hook8, ctrl, count);
}    

void drawMenu() {
	int entries = 0;
	#define MENU_OPTION_F(TEXT,...)\
		blit_set_color(0x00FFFFFF, (pos != entries) ? 0x00FF0000 : 0x0000FF00);\
		blit_stringf(LEFT_LABEL_X, 120+16*entries++, (TEXT), __VA_ARGS__);	
	#define MENU_OPTION(TEXT,...)\
		blit_set_color(0x00FFFFFF, (pos != entries) ? 0x00FF0000 : 0x0000FF00);\
		blit_stringf(LEFT_LABEL_X, 120+16*entries++, (TEXT));	
	blit_set_color(0x00FFFFFF, 0x00FF0000);
	switch(page) {
		case 0:
			blit_stringf(LEFT_LABEL_X, 88, "LOLIcon by @dots_tb");
			MENU_OPTION_F("Save for %s", titleid);
			MENU_OPTION("Save as Default");
			MENU_OPTION("Clear settings");
			MENU_OPTION("Oclock Options");
			MENU_OPTION("OSD Options");
			MENU_OPTION("Ctrl Options");
			MENU_OPTION("Exit Game");
			MENU_OPTION("Suspend vita");
			MENU_OPTION("Restart vita");
			MENU_OPTION("Shutdown vita");
			break;
		case 1:
			blit_stringf(LEFT_LABEL_X, 88, "ACTUAL OVERCLOCK");		
			blit_stringf(LEFT_LABEL_X, 120, "PROFILE    ");
			switch(current_config.mode) {
				case 4: 
					blit_stringf(RIGHT_LABEL_X, 120, "Max Batt.");
					break;
				case 3: 
					blit_stringf(RIGHT_LABEL_X, 120, "Holy Shit.");
					break;
				case 2: 
					blit_stringf(RIGHT_LABEL_X, 120, "Max Perf.");
					break;
				case 1:
					blit_stringf(RIGHT_LABEL_X, 120, "Game Def.");
					break;
				case 0:
					blit_stringf(RIGHT_LABEL_X, 120, "Default  ");
					break;
				}	
			blit_stringf(LEFT_LABEL_X, 136, "CPU CLOCK  ");
			blit_stringf(RIGHT_LABEL_X, 136, "%-4d  MHz - %d:%d", kscePowerGetArmClockFrequency(), *clock_r1, *clock_r2);
			blit_stringf(LEFT_LABEL_X, 152, "BUS CLOCK  ");
			blit_stringf(RIGHT_LABEL_X, 152, "%-4d  MHz", kscePowerGetBusClockFrequency());
			blit_stringf(LEFT_LABEL_X, 168, "GPUes4CLK  ");
			
			int r1, r2;
			kscePowerGetGpuEs4ClockFrequency(&r1, &r2);
			blit_stringf(RIGHT_LABEL_X, 168, "%-d   MHz", r1);
			blit_stringf(LEFT_LABEL_X, 184, "XBAR  CLK  ");
			blit_stringf(RIGHT_LABEL_X, 184, "%-4d  MHz", kscePowerGetGpuXbarClockFrequency());
			blit_stringf(LEFT_LABEL_X, 200, "GPU CLOCK  ");
			blit_stringf(RIGHT_LABEL_X, 200, "%-4d  MHz", kscePowerGetGpuClockFrequency());
			break;
		case 2:
			blit_stringf(LEFT_LABEL_X, 88, "OSD");	
			MENU_OPTION_F("Show FPS %d",current_config.showFPS);
			MENU_OPTION_F("Show Battery %d",current_config.showBat);
			MENU_OPTION_F("Hide Errors %d",current_config.hideErrors);
			break;
		case 3:
			blit_stringf(LEFT_LABEL_X, 88, "CONTROL");	
			MENU_OPTION_F("BUTTON SWAP %d",current_config.buttonSwap);
			break;			
	}
	if(pos >= entries)
		pos = entries -1;	
}

static tai_hook_ref_t ref_hook0;
int _sceDisplaySetFrameBufInternalForDriver(int fb_id1, int fb_id2, const SceDisplayFrameBuf *pParam, int sync){
	if(!isPspEmu && fb_id1 && pParam) {
		if(!shell_pid && fb_id2) {//3.68 fix
			if(ksceKernelGetProcessTitleId(ksceKernelGetProcessId(), titleid, sizeof(titleid))==0 && titleid[0] != 0) {
				if(strncmp("main",titleid, sizeof(titleid))==0) {
					shell_pid = ksceKernelGetProcessId();
					load_and_refresh();
				}
			}
		}
		SceDisplayFrameBuf kfb;
		memset(&kfb,0,sizeof(kfb));
		memcpy(&kfb, pParam, sizeof(SceDisplayFrameBuf));
		blit_set_frame_buf(&kfb);
		if(showMenu) drawMenu();
		
		blit_set_color(0x0000FF00, 0xff000000);
		if((isShell && shell_pid == ksceKernelGetProcessId())||(!isShell && current_pid == ksceKernelGetProcessId())) {
			drawErrors();
			curTime = ksceKernelGetProcessTimeWideCore();
			if(current_config.showFPS) doFps();
			if(current_config.showBat) blit_stringf(20, 30, "%02d\%", kscePowerGetBatteryLifePercent());
		}
		
	}
	return TAI_CONTINUE(int, ref_hook0, fb_id1, fb_id2, pParam, sync);
}

int getFindModNameFromPID(int pid, char *mod_name, int size) {
	SceKernelModuleInfo sceinfo;
	sceinfo.size = sizeof(sceinfo);
	int ret;
	size_t count;
	SceUID modids[128];		
	if((ret = ksceKernelGetModuleList(pid, 0xff, 1, modids, &count)) == 0) {
		for(int i = 0; i < count; i++) {
			if((ret = ksceKernelGetModuleInfo(pid, modids[count - 1], &sceinfo))==0) {
				if(strncmp(mod_name, sceinfo.module_name, size)==0)
					return 1;
			}
		}
		return 0;
	}
	return ret;
}

static tai_hook_ref_t process_hook0;
int SceProcEventForDriver_414CC813(int pid, int id, int r3, int r4, int r5, int r6){
	SceKernelProcessInfo info;
	info.size = 0xE8;
	char module_name[28];
	if(strncmp("main",titleid, sizeof(titleid))==0) {
		switch(id) {
			case 0x1://startup
				if(!shell_pid && ksceKernelGetProcessInfo(pid, &info) ==0 ) {
					if(info.ppid == KERNEL_PID) {
						shell_pid = pid;
						strncpy(titleid, "main", sizeof("main"));
						load_and_refresh();
						break;
					}
				}
			case 0x5:
				isPspEmu = getFindModNameFromPID(pid, "adrenaline", sizeof("adrenaline"))||getFindModNameFromPID(pid, "ScePspemu", sizeof("ScePspemu"));
				current_pid = pid;
				if(!isPspEmu) 
					forceReset = 1;
				 else {
					ksceKernelGetProcessTitleId(pid, titleid, sizeof(titleid));
					showMenu = isShell = current_config.mode = 0;
				}
				break;
		}
	} else {
		if((id==0x4 || id == 0x3)&& (current_pid==pid||isPspEmu)) {
			msg_time = curTime = fps_count = lateTime = 0;
			isShell = 1;
			strncpy(titleid, "main", sizeof("main"));
			isPspEmu =0;
			load_and_refresh();
		}
	}
	return TAI_CONTINUE(int, process_hook0, pid, id, r3, r4, r5, r6);
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {

  static devsett rmeme;

  SceUID fd;
  fd = ksceIoOpen("ur0:tai/kaio.cfg", SCE_O_RDONLY, 0777);
  ksceIoRead(fd, &rmeme, sizeof(rmeme));
  ksceIoClose(fd);
  
  if (rmeme.slots[0] == 1) {
// LOLIcon
	ksceIoMkdir(CONFIG_PATH,6);
	module_get_export_func(KERNEL_PID, "ScePower", 0x1590166F, 0x475BCC82, &_kscePowerGetGpuEs4ClockFrequency);
	module_get_export_func(KERNEL_PID, "ScePower", 0x1590166F, 0x264C24FC, &_kscePowerSetGpuEs4ClockFrequency);
	module_get_export_func(KERNEL_PID, "ScePower", 0x1590166F, 0x64641E6A, &_kscePowerGetGpuClockFrequency);
	module_get_export_func(KERNEL_PID, "ScePower", 0x1590166F, 0x621BD8FD , &_kscePowerSetGpuClockFrequency);

	tai_module_info_t tai_info;
	
	tai_info.size = sizeof(tai_module_info_t);

	clock_r1 = (unsigned int *)pa2va(0xE3103000);
	clock_r2 = (unsigned int *)pa2va(0xE3103004);	
	
	taiGetModuleInfoForKernel(KERNEL_PID, "ScePower", &tai_info);
	module_get_offset(KERNEL_PID, tai_info.modid, 1,  0x4124 + 0xA4, (uintptr_t)&clock_speed);	
	
	memset(&titleid, 0, sizeof(titleid));
	strncpy(titleid, "main", sizeof(titleid));
	reset_config();
	
	current_config.mode = 3;
	
	refreshClocks();
	
	if(module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0xC445FA63, 0xD269F915 , &_ksceKernelGetModuleInfo))
		module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0x92C9FFC2, 0xDAA90093 , &_ksceKernelGetModuleInfo);
	if(module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0xC445FA63, 0x97CF7B4E , &_ksceKernelGetModuleList))
		module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0x92C9FFC2, 0xB72C75A4 , &_ksceKernelGetModuleList);
	if(module_get_export_func(KERNEL_PID, "SceProcessmgr", 0x7A69DE86, 0x4CA7DC42 , &_ksceKernelExitProcess))
		module_get_export_func(KERNEL_PID, "SceProcessmgr", 0xEB1F8EF7, 0x905621F9 , &_ksceKernelExitProcess);

	
	g_hooks[0] = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hook0, "SceDisplay",0x9FED47AC,0x16466675, _sceDisplaySetFrameBufInternalForDriver); 
	
	
	g_hooks[10] = taiHookFunctionExportForKernel(KERNEL_PID, &power_hook1, "ScePower", 0x1590166F, 0x74DB5AE5,power_patched1); // scePowerSetArmClockFrequency
	g_hooks[11] = taiHookFunctionExportForKernel(KERNEL_PID,	&power_hook2, "ScePower", 0x1590166F, 0xB8D7B3FB, power_patched2); // scePowerSetBusClockFrequency
	g_hooks[12] = taiHookFunctionExportForKernel(KERNEL_PID, &power_hook3, "ScePower", 0x1590166F, 0x264C24FC, power_patched3); // scePowerSetGpuClockFrequency
	g_hooks[13] = taiHookFunctionExportForKernel(KERNEL_PID, &power_hook4, "ScePower", 0x1590166F, 0xA7739DBE, power_patched4); // scePowerSetGpuXbarClockFrequency
	
	taiGetModuleInfoForKernel(KERNEL_PID, "SceCtrl", &tai_info);
	g_hooks[1] = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hook1, "SceCtrl", TAI_ANY_LIBRARY, 0xEA1D3A34, keys_patched1); // sceCtrlPeekBufferPositive
	g_hooks[2] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hook2, tai_info.modid, 0, 0x3EF8, 1, keys_patched2); // sceCtrlPeekBufferPositive2
	g_hooks[3] = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hook3, "SceCtrl", TAI_ANY_LIBRARY, 0x9B96A1AA, keys_patched3); // sceCtrlReadBufferPositive
	g_hooks[4] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hook4, tai_info.modid, 0, 0x4E14, 1, keys_patched4); // sceCtrlReadBufferPositiveExt2
	g_hooks[5] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hook5, tai_info.modid, 0, 0x4B48, 1, keys_patched5); // sceCtrlPeekBufferPositiveExt2
	g_hooks[6] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hook6, tai_info.modid, 0, 0x3928, 1, keys_patched6); // sceCtrlPeekBufferPositiveExt
    g_hooks[7] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hook7, tai_info.modid, 0, 0x449C, 1, keys_patched7); // sceCtrlReadBufferPositive2
    g_hooks[8] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hook8, tai_info.modid, 0, 0x3BCC, 1, keys_patched8); // sceCtrlReadBufferPositiveExt
		  
	g_hooks[9] = taiHookFunctionImportForKernel(KERNEL_PID, &process_hook0, "SceProcessmgr", TAI_ANY_LIBRARY, 0x414CC813, SceProcEventForDriver_414CC813);
  }
  if (rmeme.slots[1] == 1) {
	// rePatch
	
		module_get_export_func(KERNEL_PID, "SceFios2Kernel", TAI_ANY_LIBRARY, 0x23247EFB, &_sceFiosKernelOverlayRemoveForProcessForDriver);
	
	hooks_uid[0] = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hooks[0], "SceFios2Kernel", TAI_ANY_LIBRARY, 0x17E65A1C, sceFiosKernelOverlayAddForProcessForDriver_patched);
	hooks_uid[1] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks[1], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0x75192972, ksceIoOpen_patched);
	hooks_uid[2] = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hooks[2], "SceAppMgr", TAI_ANY_LIBRARY, 0xEA75D157, sceAppMgrDrmOpenForDriver_patched);
	hooks_uid[3] = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hooks[3], "SceAppMgr", TAI_ANY_LIBRARY, 0x088670A6, sceAppMgrDrmCloseForDriver_patched);
	hooks_uid[4] = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hooks[4], "SceAppMgr", TAI_ANY_LIBRARY, 0xCE356B2D, ksceAppMgrGameDataMount_patched);

	tai_module_info_t tai_info2;
	
	memset(&tai_info2,0,sizeof(tai_module_info_t));
	tai_info2.size = sizeof(tai_module_info_t);
	taiGetModuleInfoForKernel(KERNEL_PID, "SceIofilemgr", &tai_info2);

	switch(tai_info2.module_nid) {
		case 0xA96ACE9D://3.65
		case 0x90DA33DE://3.68
			hooks_uid[5] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hooks[5], tai_info2.modid, 0, 0xb3d8, 1,  io_item_thing_patched);
			break;
		case 0x9642948C://3.60
			hooks_uid[5] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hooks[5], tai_info2.modid, 0, 0xd400, 1, io_item_thing_patched);
			break;
		default:
			hooks_uid[5] =  taiHookFunctionOffsetForKernel(KERNEL_PID, &ref_hooks[5], tai_info2.modid, 0, 0xb3d8, 1,  io_item_thing_patched);
			break;
	}
  }
  
  if (rmeme.slots[2] == 1) {
	// reF00D
if(GetExport("SceSysmem", 0x63A519E5, 0xC0A4D2F3, &sceSysmemMallocForKernel) < 0) {
		if(GetExport("SceSysmem", TAI_ANY_LIBRARY, 0x85571907, &sceSysmemMallocForKernel) < 0)
			return SCE_KERNEL_START_FAILED;
	}
	if(GetExport("SceSysmem", 0x63A519E5, 0xABAB0FAB, &sceSysmemFreeForKernel) < 0) {
		if(GetExport("SceSysmem", TAI_ANY_LIBRARY, 0x4233C16D, &sceSysmemFreeForKernel) < 0)
			return SCE_KERNEL_START_FAILED;	
	}
		
	if(GetExport("SceSblSsMgr", TAI_ANY_LIBRARY, 0x121FA69F, &sceSblSsMgrAESCBCDecryptForDriver) < 0)
		return SCE_KERNEL_START_FAILED;	
	
	if((hooks_uid_rf[0] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks_rf[0], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0x75192972, ksceIoOpen_patched_rf)) < 0)
		return SCE_KERNEL_START_FAILED;	
	
	if((hooks_uid_rf[1] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks_rf[1], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0xBC422443, decrypt_buffer_patched)) < 0)
		return SCE_KERNEL_START_FAILED;	

	SceUID fd = ksceIoOpen(REF00D_KEYS, SCE_O_RDONLY, 0);
	if (fd >= 0) {
		KeyHeader hdr;
		ksceIoRead(fd, &hdr, sizeof(KeyHeader));
		if(hdr.magic == 0x53504146)  {
			current_key = hdr.num_of_keys;
			ksceIoRead(fd, &KEYS, hdr.key_size*current_key);
		}
		ksceIoClose(fd);
	}
  }
  
  if (rmeme.slots[3] == 1) {
	// NoNpDrm
	  hooks[n_hooks] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceKernelLaunchAppRef, "SceProcessmgr",
                                                  0x7A69DE86, 0x71CF71FD, ksceKernelLaunchAppPatched);
  if (hooks[n_hooks] < 0)
    hooks[n_hooks] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceKernelLaunchAppRef, "SceProcessmgr",
                                                    0xEB1F8EF7, 0x68068618, ksceKernelLaunchAppPatched);
  n_hooks++;

  hooks[n_hooks++] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceNpDrmGetRifInfoRef, "SceNpDrm",
                                                    0xD84DC44A, 0xDB406EAE, ksceNpDrmGetRifInfoPatched);
  hooks[n_hooks++] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceNpDrmGetRifVitaKeyRef, "SceNpDrm",
                                                    0xD84DC44A, 0x723322B5, ksceNpDrmGetRifVitaKeyPatched);
  hooks[n_hooks++] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceNpDrmGetRifNameRef, "SceNpDrm",
                                                    0xD84DC44A, 0xDF62F3B8, ksceNpDrmGetRifNamePatched);
  hooks[n_hooks++] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceNpDrmGetRifNameForInstallRef, "SceNpDrm",
                                                    0xD84DC44A, 0x17573133, ksceNpDrmGetRifNameForInstallPatched);
  }
                                                    
  if (rmeme.slots[4] == 1) {
    //NoAvls
    hook = taiHookFunctionExportForKernel(KERNEL_PID,
		&ref_hook, 
		"SceAVConfig",
		TAI_ANY_LIBRARY,
		0x830b950b, 
		sceAVConfigGetVolCtrlEnable_patched);
  }
                                                    
  if (rmeme.slots[5] == 1) {                                  
    // ioPlus
    hook_iop = taiHookFunctionExportForKernel(KERNEL_PID, &ref_hook_iop, "SceFios2Kernel", TAI_ANY_LIBRARY, 0x0F456345, sceFiosKernelOverlayResolveSyncForDriver_patched);
  }
  
  if (rmeme.slots[6] == 1) {
    // gamesd
    patch_sdstor();
	patch_appmgr();
	poke_gamecard();
	redirect_ux0();
  }
		
	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
	// free hooks that didn't fail
	if (g_hooks[0] >= 0) taiHookReleaseForKernel(g_hooks[0], ref_hook0);
	if (g_hooks[1] >= 0) taiHookReleaseForKernel(g_hooks[1], ref_hook1);
	if (g_hooks[2] >= 0) taiHookReleaseForKernel(g_hooks[2], ref_hook2);
	if (g_hooks[3] >= 0) taiHookReleaseForKernel(g_hooks[3], ref_hook3);
	if (g_hooks[4] >= 0) taiHookReleaseForKernel(g_hooks[4], ref_hook4);
	if (g_hooks[5] >= 0) taiHookReleaseForKernel(g_hooks[5], ref_hook5);
	if (g_hooks[6] >= 0) taiHookReleaseForKernel(g_hooks[6], ref_hook6);
	if (g_hooks[7] >= 0) taiHookReleaseForKernel(g_hooks[7], ref_hook7);
	if (g_hooks[8] >= 0) taiHookReleaseForKernel(g_hooks[8], ref_hook8);
	if (g_hooks[9] >= 0) taiHookReleaseForKernel(g_hooks[9], process_hook0);
	if (g_hooks[10] >= 0) taiHookReleaseForKernel(g_hooks[10], power_hook1);
	if (g_hooks[11] >= 0) taiHookReleaseForKernel(g_hooks[11], power_hook2);
	if (g_hooks[12] >= 0) taiHookReleaseForKernel(g_hooks[12], power_hook3);
	if (g_hooks[13] >= 0) taiHookReleaseForKernel(g_hooks[13], power_hook4);
	for (int i=0; i < HOOKS_NUMBER; i++)
		if (hooks_uid[i] >= 0) taiHookReleaseForKernel(hooks_uid[i], ref_hooks[i]); 
	  if (hooks[--n_hooks] >= 0)
    taiHookReleaseForKernel(hooks[n_hooks], ksceNpDrmGetRifNameForInstallRef);
  if (hooks[--n_hooks] >= 0)
    taiHookReleaseForKernel(hooks[n_hooks], ksceNpDrmGetRifNameRef);
  if (hooks[--n_hooks] >= 0)
    taiHookReleaseForKernel(hooks[n_hooks], ksceNpDrmGetRifVitaKeyRef);
  if (hooks[--n_hooks] >= 0)
    taiHookReleaseForKernel(hooks[n_hooks], ksceNpDrmGetRifInfoRef);
  if (hooks[--n_hooks] >= 0)
    taiHookReleaseForKernel(hooks[n_hooks], ksceKernelLaunchAppRef);  
    
    if (hook >= 0) taiHookReleaseForKernel(hook, ref_hook);  
    
    if (hook_iop >= 0) taiHookReleaseForKernel(hook_iop, ref_hook_iop);

	return SCE_KERNEL_STOP_SUCCESS;
}
