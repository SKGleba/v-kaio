TITLE_ID = SKGVKAIO1
TARGET   = vkaio
OBJS     = main.o font.o graphics.o

LIBS = -lSceDisplay_stub \
  -lSceCtrl_stub \
  -lSceProcessmgr_stub \
  -lScePower_stub \
  -lSceRegistryMgr_stub \
  -lSceAppMgr_stub \
  -lSceVshBridge_stub \

PREFIX  = arm-vita-eabi
CC      = $(PREFIX)-gcc
CFLAGS  = -Wl,-q -Wall -fno-lto
ASFLAGS = $(CFLAGS)

all: $(TARGET).vpk

%.vpk: eboot.bin
	vita-mksfoex -s TITLE_ID=$(TITLE_ID) "VKAIO" param.sfo
	vita-pack-vpk -s param.sfo -b eboot.bin \
    -a sce_sys/icon0.png=sce_sys/icon0.png \
    -a plugin/kplugin.skprx=kplugin.skprx \
    -a sce_sys/livearea/contents/bg.png=sce_sys/livearea/contents/bg.png \
    -a sce_sys/livearea/contents/template.xml=sce_sys/livearea/contents/template.xml \$@

eboot.bin: $(TARGET).velf
	vita-make-fself -c $< $@

%.velf: %.elf
	vita-elf-create $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

%.o: %.png
	$(PREFIX)-ld -r -b binary -o $@ $^

clean:
	@rm -rf $(TARGET).vpk $(TARGET).velf $(TARGET).elf $(OBJS) \
		eboot.bin param.sfo

vpksend: $(TARGET).vpk
	curl -T $(TARGET).vpk ftp://$(PSVITAIP):1337/ux0:/
	@echo "Sent."

send: eboot.bin
	curl -T eboot.bin ftp://$(PSVITAIP):1337/ux0:/app/$(TITLE_ID)/
	@echo "Sent."
