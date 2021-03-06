LWIPDIR=		$(VENDORDIR)/lwip
MBEDTLS_DIR=	$(VENDORDIR)/mbedtls

PROGRAMS= \
	cloud_init \
	ntp \
	radar \
	test \
	tls \

SRCS-cloud_init= \
	$(CURDIR)/cloud_azure.c \
	$(CURDIR)/cloud_init.c \

SRCS-ntp= \
	$(CURDIR)/ntp.c \

SRCS-radar= \
	$(CURDIR)/radar.c \

SRCS-test= \
	$(CURDIR)/test.c

SRCS-tls= \
	$(CURDIR)/mbedtls.c \
	$(SRCS-mbedtls)

SRCS-mbedtls= $(SRCS-mbedtls-crypto) $(SRCS-mbedtls-x509) $(SRCS-mbedtls-tls)

SRCS-mbedtls-crypto= \
	$(MBEDTLS_DIR)/library/aes.c \
	$(MBEDTLS_DIR)/library/arc4.c \
	$(MBEDTLS_DIR)/library/aria.c \
	$(MBEDTLS_DIR)/library/asn1parse.c \
	$(MBEDTLS_DIR)/library/asn1write.c \
	$(MBEDTLS_DIR)/library/base64.c \
	$(MBEDTLS_DIR)/library/bignum.c \
	$(MBEDTLS_DIR)/library/blowfish.c \
	$(MBEDTLS_DIR)/library/camellia.c \
	$(MBEDTLS_DIR)/library/ccm.c \
	$(MBEDTLS_DIR)/library/chacha20.c \
	$(MBEDTLS_DIR)/library/chachapoly.c \
	$(MBEDTLS_DIR)/library/cipher.c \
	$(MBEDTLS_DIR)/library/cipher_wrap.c \
	$(MBEDTLS_DIR)/library/cmac.c \
	$(MBEDTLS_DIR)/library/ctr_drbg.c \
	$(MBEDTLS_DIR)/library/des.c \
	$(MBEDTLS_DIR)/library/dhm.c \
	$(MBEDTLS_DIR)/library/ecdh.c \
	$(MBEDTLS_DIR)/library/ecdsa.c \
	$(MBEDTLS_DIR)/library/ecjpake.c \
	$(MBEDTLS_DIR)/library/ecp.c \
	$(MBEDTLS_DIR)/library/ecp_curves.c \
	$(MBEDTLS_DIR)/library/entropy.c \
	$(MBEDTLS_DIR)/library/entropy_poll.c \
	$(MBEDTLS_DIR)/library/gcm.c \
	$(MBEDTLS_DIR)/library/havege.c \
	$(MBEDTLS_DIR)/library/hkdf.c \
	$(MBEDTLS_DIR)/library/hmac_drbg.c \
	$(MBEDTLS_DIR)/library/md.c \
	$(MBEDTLS_DIR)/library/md2.c \
	$(MBEDTLS_DIR)/library/md4.c \
	$(MBEDTLS_DIR)/library/md5.c \
	$(MBEDTLS_DIR)/library/memory_buffer_alloc.c \
	$(MBEDTLS_DIR)/library/nist_kw.c \
	$(MBEDTLS_DIR)/library/oid.c \
	$(MBEDTLS_DIR)/library/padlock.c \
	$(MBEDTLS_DIR)/library/pem.c \
	$(MBEDTLS_DIR)/library/pk.c \
	$(MBEDTLS_DIR)/library/pk_wrap.c \
	$(MBEDTLS_DIR)/library/pkcs12.c \
	$(MBEDTLS_DIR)/library/pkcs5.c \
	$(MBEDTLS_DIR)/library/pkparse.c \
	$(MBEDTLS_DIR)/library/pkwrite.c \
	$(MBEDTLS_DIR)/library/platform.c \
	$(MBEDTLS_DIR)/library/platform_util.c \
	$(MBEDTLS_DIR)/library/poly1305.c \
	$(MBEDTLS_DIR)/library/psa_crypto.c \
	$(MBEDTLS_DIR)/library/psa_crypto_se.c \
	$(MBEDTLS_DIR)/library/psa_crypto_slot_management.c \
	$(MBEDTLS_DIR)/library/psa_its_file.c \
	$(MBEDTLS_DIR)/library/ripemd160.c \
	$(MBEDTLS_DIR)/library/rsa.c \
	$(MBEDTLS_DIR)/library/rsa_internal.c \
	$(MBEDTLS_DIR)/library/sha1.c \
	$(MBEDTLS_DIR)/library/sha256.c \
	$(MBEDTLS_DIR)/library/sha512.c \
	$(MBEDTLS_DIR)/library/threading.c \
	$(MBEDTLS_DIR)/library/version.c \
	$(MBEDTLS_DIR)/library/version_features.c \
	$(MBEDTLS_DIR)/library/xtea.c \

SRCS-mbedtls-x509= \
	$(MBEDTLS_DIR)/library/certs.c \
	$(MBEDTLS_DIR)/library/pkcs11.c \
	$(MBEDTLS_DIR)/library/x509.c \
	$(MBEDTLS_DIR)/library/x509_crt.c \

SRCS-mbedtls-tls= \
	$(MBEDTLS_DIR)/library/ssl_cache.c \
	$(MBEDTLS_DIR)/library/ssl_ciphersuites.c \
	$(MBEDTLS_DIR)/library/ssl_cli.c \
	$(MBEDTLS_DIR)/library/ssl_cookie.c \
	$(MBEDTLS_DIR)/library/ssl_msg.c \
	$(MBEDTLS_DIR)/library/ssl_srv.c \
	$(MBEDTLS_DIR)/library/ssl_ticket.c \
	$(MBEDTLS_DIR)/library/ssl_tls.c \

all: $(PROGRAMS)

include ../rules.mk

ifeq ($(UNAME_s),Darwin)
ELF_TARGET=     -target x86_64-elf
CFLAGS+=        $(ELF_TARGET)
LD=             x86_64-elf-ld
OBJDUMP=        x86_64-elf-objdump
else
LD=             $(CROSS_COMPILE)ld
endif

INCLUDES= \
	-I$(CURDIR) \
	-I$(ARCHDIR) \
	-I$(LWIPDIR)/src/include \
	-I$(MBEDTLS_DIR)/include \
	-I$(SRCDIR) \
	-I$(SRCDIR)/http \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/net \
	-I$(SRCDIR)/runtime \
	-I$(PLATFORMDIR)

DEFINES= \
	-DKLIB \
	-DMBEDTLS_USER_CONFIG_FILE=\"mbedtls_conf.h\" \

CFLAGS+=	$(KERNCFLAGS) $(INCLUDES) -fPIC $(DEFINES)

# TODO should add stack protection to klibs...
CFLAGS+=	-fno-stack-protector
LDFLAGS+=	-pie -nostdlib -T$(ARCHDIR)/klib.lds

CLEANDIRS+=	$(OUTDIR)/klib/vendor $(OUTDIR)/klib/vendor/mbedtls
