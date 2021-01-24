/**
 * Contains OS-level routines needed by the garbage collector.
 *
 * Copyright: D Language Foundation 2005 - 2021.
 * License:   $(HTTP www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
 * Authors:   Walter Bright, David Friedman, Sean Kelly, Leandro Lucarella
 */
module agora.utils.gc.os;


version (Windows)
{
    import core.sys.windows.winbase : GetCurrentThreadId, VirtualAlloc, VirtualFree;
    import core.sys.windows.winnt : MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE;

    alias int pthread_t;

    pthread_t pthread_self() nothrow
    {
        return cast(pthread_t) GetCurrentThreadId();
    }

    //version = GC_Use_Alloc_Win32;
}
else version (Posix)
{
    version (OSX)
        version = Darwin;
    else version (iOS)
        version = Darwin;
    else version (TVOS)
        version = Darwin;
    else version (WatchOS)
        version = Darwin;

    import core.sys.posix.sys.mman;
    import core.stdc.stdlib;

    //version = GC_Use_Alloc_MMap;
}
else
{
    import core.stdc.stdlib;

    //version = GC_Use_Alloc_Malloc;
}

/+
static if (is(typeof(VirtualAlloc)))
    version = GC_Use_Alloc_Win32;
else static if (is(typeof(mmap)))
    version = GC_Use_Alloc_MMap;
else static if (is(typeof(valloc)))
    version = GC_Use_Alloc_Valloc;
else static if (is(typeof(malloc)))
    version = GC_Use_Alloc_Malloc;
else static assert(false, "No supported allocation methods available.");
+/

static if (is(typeof(VirtualAlloc))) // version (GC_Use_Alloc_Win32)
{
    /**
     * Map memory.
     */
    void *os_mem_map(size_t nbytes) nothrow
    {
        return VirtualAlloc(null, nbytes, MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE);
    }


    /**
     * Unmap memory allocated with os_mem_map().
     * Returns:
     *      0       success
     *      !=0     failure
     */
    int os_mem_unmap(void *base, size_t nbytes) nothrow
    {
        return cast(int)(VirtualFree(base, 0, MEM_RELEASE) == 0);
    }
}
else static if (is(typeof(mmap)))  // else version (GC_Use_Alloc_MMap)
{
    void *os_mem_map(size_t nbytes) nothrow
    {   void *p;

        p = mmap(null, nbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        return (p == MAP_FAILED) ? null : p;
    }


    int os_mem_unmap(void *base, size_t nbytes) nothrow
    {
        return munmap(base, nbytes);
    }
}
else static if (is(typeof(valloc))) // else version (GC_Use_Alloc_Valloc)
{
    void *os_mem_map(size_t nbytes) nothrow
    {
        return valloc(nbytes);
    }


    int os_mem_unmap(void *base, size_t nbytes) nothrow
    {
        free(base);
        return 0;
    }
}
else static if (is(typeof(malloc))) // else version (GC_Use_Alloc_Malloc)
{
    // NOTE: This assumes malloc granularity is at least (void*).sizeof.  If
    //       (req_size + PAGESIZE) is allocated, and the pointer is rounded up
    //       to PAGESIZE alignment, there will be space for a void* at the end
    //       after PAGESIZE bytes used by the GC.


    import core.internal.gc.impl.conservative.gc;


    const size_t PAGE_MASK = PAGESIZE - 1;


    void *os_mem_map(size_t nbytes) nothrow
    {   byte *p, q;
        p = cast(byte *) malloc(nbytes + PAGESIZE);
        if (!p)
            return null;
        q = p + ((PAGESIZE - ((cast(size_t) p & PAGE_MASK))) & PAGE_MASK);
        * cast(void**)(q + nbytes) = p;
        return q;
    }


    int os_mem_unmap(void *base, size_t nbytes) nothrow
    {
        free( *cast(void**)( cast(byte*) base + nbytes ) );
        return 0;
    }
}
else
{
    static assert(false, "No supported allocation methods available.");
}

/**
   Check for any kind of memory pressure.

   Params:
      mapped = the amount of memory mapped by the GC in bytes
   Returns:
       true if memory is scarce
*/
// TOOD: get virtual mem sizes and current usage from OS
// TODO: compare current RSS and avail. physical memory
version (Windows)
{
    bool isLowOnMem(size_t mapped) nothrow @nogc
    {
        version (D_LP64)
            return false;
        else
        {
            import core.sys.windows.winbase : GlobalMemoryStatus, MEMORYSTATUS;
            MEMORYSTATUS stat;
            GlobalMemoryStatus(&stat);
            // Less than 5 % of virtual address space available
            return stat.dwAvailVirtual < stat.dwTotalVirtual / 20;
        }
    }
}
else version (Darwin)
{
    bool isLowOnMem(size_t mapped) nothrow @nogc
    {
        enum GB = 2 ^^ 30;
        version (D_LP64)
            return false;
        else
        {
            // 80 % of available 4GB is used for GC (excluding malloc and mmap)
            enum size_t limit = 4UL * GB * 8 / 10;
            return mapped > limit;
        }
    }
}
else
{
    bool isLowOnMem(size_t mapped) nothrow @nogc
    {
        enum GB = 2 ^^ 30;
        version (D_LP64)
            return false;
        else
        {
            // be conservative and assume 3GB
            enum size_t limit = 3UL * GB * 8 / 10;
            return mapped > limit;
        }
    }
}

/**
   Get the size of available physical memory

   Returns:
       size of installed physical RAM
*/
version (Windows)
{
    ulong os_physical_mem() nothrow @nogc
    {
        import core.sys.windows.winbase : GlobalMemoryStatus, MEMORYSTATUS;
        MEMORYSTATUS stat;
        GlobalMemoryStatus(&stat);
        return stat.dwTotalPhys; // limited to 4GB for Win32
    }
}
else version (Darwin)
{
    extern (C) int sysctl(const int* name, uint namelen, void* oldp, size_t* oldlenp, const void* newp, size_t newlen) @nogc nothrow;
    ulong os_physical_mem() nothrow @nogc
    {
        enum
        {
            CTL_HW = 6,
            HW_MEMSIZE = 24,
        }
        int[2] mib = [ CTL_HW, HW_MEMSIZE ];
        ulong system_memory_bytes;
        size_t len = system_memory_bytes.sizeof;
        if (sysctl(mib.ptr, 2, &system_memory_bytes, &len, null, 0) != 0)
            return 0;
        return system_memory_bytes;
    }
}
else version (Posix)
{
    ulong os_physical_mem() nothrow @nogc
    {
        import core.sys.posix.unistd : sysconf, _SC_PAGESIZE, _SC_PHYS_PAGES;
        const pageSize = sysconf(_SC_PAGESIZE);
        const pages = sysconf(_SC_PHYS_PAGES);
        return pageSize * pages;
    }
}
