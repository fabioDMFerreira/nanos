# these are built for the target platform (Linux x86_64)
PROGRAMS= \
	creat \
	fst \
	getdents \
	getrandom \
	hw \
	hwg \
	hws \
	mkdir \
	pipe \
	sendfile \
	time \
	udploop \
	web \
	webg \
	webs \
	write

SRCS-creat=		$(CURDIR)/creat.c
LDFLAGS-creat=		-static

SRCS-getdents=		$(CURDIR)/getdents.c
LDFLAGS-getdents=	-static

SRCS-getrandom=		$(CURDIR)/getrandom.c
LDFLAGS-getrandom=	-static
LIBS-getrandom=		-lm

SRCS-hw=		$(CURDIR)/hw.c

SRCS-hws=		$(SRCS-hw)
LDFLAGS-hws=		-static

SRCS-mkdir=		$(CURDIR)/mkdir.c
LDFLAGS-mkdir=		-static

SRCS-pipe= \
	$(CURDIR)/pipe.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix/path.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/debug_heap.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/heap/mcache.c
LDFLAGS-pipe=		-static
LIBS-pipe=		-lm -lpthread

SRCS-sendfile=		$(CURDIR)/sendfile.c
LDFLAGS-sendfile=	-static

SRCS-time=		$(CURDIR)/time.c
LDFLAGS-time=		-static

SRCS-udploop= \
	$(CURDIR)/udploop.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/http.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c \
	$(SRCDIR)/unix/path.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/debug_heap.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/heap/mcache.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/sha256.c \
	$(SRCDIR)/runtime/signature.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c
LDFLAGS-udploop=	 -static

SRCS-web= \
	$(CURDIR)/web.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/http.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c \
	$(SRCDIR)/unix/path.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/debug_heap.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/heap/mcache.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/sha256.c \
	$(SRCDIR)/runtime/signature.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c

SRCS-webs=		$(SRCS-web)
LDFLAGS-webs=		-static

SRCS-write=		$(CURDIR)/write.c
LDFLAGS-write=		-static

CFLAGS+=	-DHOST_BUILD \
		-DENABLE_MSG_DEBUG
CFLAGS+=	-I$(SRCDIR)/runtime \
		-I$(SRCDIR)/unix \
		-I$(SRCDIR)/unix_process \
		-I$(SRCDIR)/x86_64

CLEANDIRS+=	$(OBJDIR)/test

all: $(PROGRAMS)

include ../../rules.mk

ifeq ($(UNAME_s),Darwin)
CFLAGS+=	-target x86_64-elf --sysroot $(TARGET_ROOT)
LD=		x86_64-elf-ld
LDFLAGS+=	--sysroot=$(TARGET_ROOT)
OBJS_BEGIN=	$(OBJS_CRTBEGIN)
OBJS_END=	$(OBJS_CRTEND)
GO_ENV=		GOOS=linux GOARCH=amd64

$(PROG-hw): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(PROG-hw): OBJS_END=$(OBJS_CRTEND_D)

$(PROG-web): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(PROG-web): OBJS_END=$(OBJS_CRTEND_D)
endif