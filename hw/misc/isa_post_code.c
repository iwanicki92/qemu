/*
 * POST code capture on I/O ports 0x80 to 0x83
 *
 * Firmware and loaders report progress by writing POST codes to port 0x80,
 * often as a dword that spans 0x80 to 0x83. The PC machines give port 0x80
 * a one-byte sink, so a dword write reaches it as its low byte only. This
 * device overlays all four ports and writes every access to a chardev, one
 * line each, as the port, the access size and the value. It shadows the DMA
 * page registers at 0x81 to 0x83 while present.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "chardev/char-fe.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "hw/isa/isa.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qom/object.h"
#include "trace.h"

#define TYPE_ISA_POST_CODE "isa-post-code"
OBJECT_DECLARE_SIMPLE_TYPE(ISAPostCodeState, ISA_POST_CODE)

#define POST_CODE_BASE 0x80
#define POST_CODE_PORTS 4

struct ISAPostCodeState {
    ISADevice parent_obj;

    MemoryRegion io;
    CharFrontend chr;
};

static void post_code_write(void *opaque, hwaddr addr, uint64_t value,
                            unsigned size)
{
    ISAPostCodeState *s = opaque;
    char *line;

    trace_isa_post_code_write(POST_CODE_BASE + addr, size, value);
    if (!qemu_chr_fe_backend_connected(&s->chr)) {
        return;
    }
    line = g_strdup_printf("0x%02" HWADDR_PRIx " %u 0x%0*" PRIx64 "\n",
                           POST_CODE_BASE + addr, size, size * 2, value);
    qemu_chr_fe_write_all(&s->chr, (const uint8_t *)line, strlen(line));
    g_free(line);
}

/* Reads answer as the PC's own port 0x80 sink does. */
static uint64_t post_code_read(void *opaque, hwaddr addr, unsigned size)
{
    return UINT64_MAX;
}

static const MemoryRegionOps post_code_ops = {
    .read = post_code_read,
    .write = post_code_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static void post_code_realize(DeviceState *dev, Error **errp)
{
    ISAPostCodeState *s = ISA_POST_CODE(dev);

    memory_region_init_io(&s->io, OBJECT(dev), &post_code_ops, s,
                          TYPE_ISA_POST_CODE, POST_CODE_PORTS);
    /* Above the machine's own port 0x80 sink and the DMA page registers. */
    memory_region_add_subregion_overlap(isa_address_space_io(ISA_DEVICE(dev)),
                                        POST_CODE_BASE, &s->io, 1);
}

static const Property post_code_properties[] = {
    DEFINE_PROP_CHR("chardev", ISAPostCodeState, chr),
};

static void post_code_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = post_code_realize;
    dc->desc = "POST code capture on ports 0x80 to 0x83";
    device_class_set_props(dc, post_code_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo post_code_info = {
    .name          = TYPE_ISA_POST_CODE,
    .parent        = TYPE_ISA_DEVICE,
    .instance_size = sizeof(ISAPostCodeState),
    .class_init    = post_code_class_init,
};

static void post_code_register_types(void)
{
    type_register_static(&post_code_info);
}

type_init(post_code_register_types)
