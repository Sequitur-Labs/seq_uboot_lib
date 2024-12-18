ifdef CONFIG_SPL_BUILD
obj-y	+= uECC.o seq_ecc_utils.o seq_ecc_certificate.o
obj-y	+= seq_boot_manifests.o
obj-y	+= seq_error.o
obj-y 	+= seq_activation.o
obj-$(CONFIG_CORETEE_PROV_TESTS) += seq_tests.o
obj-y +=  seq_asn1/seq_asn1_encode.o seq_asn1/seq_asn1_parse.o seq_asn1/seq_asn1_utils.o
obj-y +=  seq_manifest/seq_list.o  seq_manifest/seq_manifest.o
endif

ifneq (,$(filter $(SOC), imx8m imx8))
obj-y += arch/arm/mach-imx/
endif

