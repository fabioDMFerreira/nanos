#include <kernel.h>

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

clock_now platform_monotonic_now;
clock_timer platform_timer;
thunk platform_timer_percpu_init;

void kernel_delay(timestamp delta)
{
    timestamp end = now(CLOCK_ID_MONOTONIC) + delta;
    while (now(CLOCK_ID_MONOTONIC) < end)
        kern_pause();
}

void init_clock(void)
{
    /* detect rdtscp */
    u32 regs[4];
    cpuid(0x80000001, 0, regs);
    __vdso_dat->clock_src = VDSO_CLOCK_SYSCALL;
    __vdso_dat->platform_has_rdtscp = (regs[3] & U64_FROM_BIT(27)) != 0;
}

timestamp kern_now(clock_id id)
{
    return now(id);
}
KLIB_EXPORT_RENAME(kern_now, now);

void clock_adjust(timestamp wallclock_now, double temp_cal, timestamp sync_complete, double cal)
{
    __vdso_dat->temp_cal = temp_cal;
    __vdso_dat->sync_complete = sync_complete;
    __vdso_dat->cal = cal;
    rtc_settimeofday(sec_from_timestamp(wallclock_now));
    clock_update_drift(now(CLOCK_ID_MONOTONIC_RAW));
    timer_reorder(runloop_timers);
}
KLIB_EXPORT(clock_adjust);
