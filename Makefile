ifdef CONFIG_SPL_BUILD
obj-y	+= uECC.o seq_ecc_utils.o seq_ecc_certificate.o
obj-y	+= seq_boot_manifests.o
obj-y	+= seq_error.o
obj-y 	+= seq_activation.o
obj-$(CONFIG_CORETEE_PROV_TESTS) += seq_tests.o
endif

ifneq (,$(filter $(SOC), imx8m imx8))
obj-y += arch/arm/mach-imx/
endif

