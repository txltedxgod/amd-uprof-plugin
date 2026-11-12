/* Timer-capture fixture workload: a byte hash in the program's own code plus one heap
 * allocation and release per block, so the OS heap (ntdll.dll) carries a measurable share of
 * the CPU time. Deterministic: fixed rounds and block sizes. Freestanding: no C runtime, only
 * kernel32 imports. */

typedef void *HANDLE;
__declspec(dllimport) HANDLE __stdcall GetProcessHeap(void);
__declspec(dllimport) void *__stdcall HeapAlloc(HANDLE heap, unsigned long flags, unsigned long long size);
__declspec(dllimport) int __stdcall HeapFree(HANDLE heap, unsigned long flags, void *block);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned int code);

#define ROUNDS 6000u
#define BLOCKS 1024u

__declspec(noinline) static void fill_block(unsigned char *p, unsigned n, unsigned seed)
{
    for (unsigned i = 0; i < n; ++i)
        p[i] = (unsigned char)(seed + i * 31u);
}

__declspec(noinline) static unsigned hash_block(const unsigned char *p, unsigned n)
{
    unsigned h = 2166136261u;
    for (unsigned i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

void heap_churn_entry(void)
{
    HANDLE heap = GetProcessHeap();
    unsigned acc = 0;
    for (unsigned round = 0; round < ROUNDS; ++round) {
        for (unsigned k = 0; k < BLOCKS; ++k) {
            unsigned n = 64u + (k & 7u) * 16u;
            unsigned char *buf = (unsigned char *)HeapAlloc(heap, 0, n);
            fill_block(buf, n, round ^ k);
            acc += hash_block(buf, n);
            HeapFree(heap, 0, buf);
        }
    }
    ExitProcess(acc & 1u);
}
