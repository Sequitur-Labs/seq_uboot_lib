ifeq ($(CONFIG_SPL_BUILD),y)
obj-$(CONFIG_CORETEE) += seq_blob.o seq_bootstates.o seq_boot.o seq_memio.o seq_update.o seq_cipher.o seq_keys.o seq_rng.o
obj-$(CONFIG_SPL_SLIPROV) += seq_prov.o
else
obj-$(CONFIG_CORETEE) += seq_memio.o seq_boot.o
endif

