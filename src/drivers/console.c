#include <runtime.h>
#include "console.h"
#include "serial.h"
#include "vga.h"
#include "lock.h"

static void serial_console_write(void *d, char *s, bytes count)
{
    for (; count--; s++) {
        serial_putchar(*s);
    }
}

struct console_driver serial_console_driver = {
    .write = serial_console_write
};

struct console_driver *console_drivers[4] = {
    &serial_console_driver,
};

static u64 write_lock;

void console_write(char *s, bytes count)
{
    spin_lock(&write_lock);
    for (struct console_driver **pd = console_drivers; *pd; pd++) {
        (*pd)->write(*pd, s, count);
    }
    spin_unlock(&write_lock);
}

closure_function(0, 1, void, attach_console,
                 struct console_driver *, d)
{
    struct console_driver **pd;

    for (pd = console_drivers; *pd; pd++)
        ;
    // last console driver elem is reserved for EOL marker
    assert(pd < console_drivers + _countof(console_drivers) - 1);

    *pd = d;
}

void init_console(kernel_heaps kh)
{
    heap h = heap_general(kh);
    vga_pci_register(kh, closure(h, attach_console));
}
