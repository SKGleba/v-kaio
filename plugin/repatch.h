/* 
rePatch v3.0 reDux0 -- PATCHING WITH FREEDOM
	Brought to you by SilicaTeam 2.0 --
	
		Dev and "reV ur engines" by @dots_tb @CelesteBlue123 (especially his """holy grail"""  and self_auth info)
		
	with support from @Nkekev @SilicaAndPina

Testing team:
    AlternativeZero	bopz
	@IcySon55		DuckySushi
	AnalogMan		Pingu (@mcdarkjedii) 
	amadeus			jeff7360
	Radziu (@AluProductions)
	@RealYoti		@froid_san
	waterflame
	
Special thanks to:
	VitaPiracy, especially Radziu for shilling it
	The translation community for being supportive of rePatch and its development
	Motoharu for his RE work on the wiki
	TheFlow for creating a need for this plugin
*/

#define rePatchFolder "rePatch"
#define addcontFolder "reAddcont"

//https://wiki.henkaku.xyz/vita/SceIofilemgr
typedef struct io_scheduler_item //size is 0x14 - allocated from SceIoScheduler heap
{
   uint32_t* unk_0; // parent
   uint32_t unk_4; // 0
   uint32_t unk_8; // 0
   uint32_t unk_C; // 0
   uint32_t unk_10; // pointer to unknown module data section
} io_scheduler_item;

typedef struct drm_opts {
	uint32_t size;
	char adcont_id[20];
	char mount_point[10];
} drm_opts;

typedef struct mount_point_overlay{
  uint8_t type;
  uint8_t order;
  uint16_t dst_len;
  uint16_t src_len;
  uint32_t PID;
  uint32_t mountId;
  char dst[292];
  char src[292];
} mount_point_overlay;


//File resolver options
#define PATCH_PATH 0x01
#define DLC_PATH   0x02
#define AIDS_PATH  0x04
#define MANU_PATH  0x08
#define APP_PATH  0x10

#define DEVICES_AMT 5

const char *DEVICES[DEVICES_AMT]= {"ux0:", "uma0:", "imc0:", "grw0:", "xmc0:"};
