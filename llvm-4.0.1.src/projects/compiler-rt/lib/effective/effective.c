/*
 *        __  __           _   _           ____
 *   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
 *  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
 * |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
 *  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
 *
 * Gregory J. Duck.
 *
 * Copyright (c) 2018 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lowfat.h"
#include "effective.h"

/*
 * A conservative guess for LOWFAT_NUM_REGIONS.  The value 127 allows for
 * compact code, so is a good choice.
 */
#define EFFECTIVE_LOWFAT_NUM_REGIONS_LIMIT  127

/*
 * Calculate the intersection between two bounds:
 *   bounds3 = {max(bounds1[0], bounds2[0]), min(bounds1[1], bounds2[1])}
 */
EFFECTIVE_BOUNDS effective_bounds_narrow(EFFECTIVE_BOUNDS bounds1,
    EFFECTIVE_BOUNDS bounds2)
{
    EFFECTIVE_BOUNDS cmp = (bounds1 > bounds2);
    cmp ^= EFFECTIVE_BOUNDS_NEG_1_0;
    EFFECTIVE_BOUNDS bounds3 =
        __builtin_ia32_pblendvb128(bounds1, bounds2, cmp);
    return bounds3;
}

EFFECTIVE_HOT EFFECTIVE_BOUNDS effective_type_prefetch(const void *ptr,
    const EFFECTIVE_TYPE *u)
{

}


/*
 * Do a type check and calculate the (sub-object) bounds.
 *
 * This function is highly optimized for clang-4.0.
 * - no register spills.
 * - the loop exit (success) always jumps to the same location.
 * - instruction ordering matters.
 * The fast-path (excluding non-fat pointers) is ~50 (low-medium latency)
 * instructions and 4 memory access (excluding low-fat tables & stack).
 */
EFFECTIVE_HOT EFFECTIVE_BOUNDS effective_type_check(const void *ptr,
    const EFFECTIVE_TYPE *u)
{
    size_t idx = lowfat_index(ptr);
    if (idx > EFFECTIVE_LOWFAT_NUM_REGIONS_LIMIT || _LOWFAT_MAGICS[idx] == 0)
    {
        // `ptr' is a non-fat-pointer, meaning that there is no object
        // meta-data associated with it.  For such pointers we return "wide"
        // bounds that are unlikely to trigger a bounds error, but narrow
        // enough to protect objects allocated in the low-fat regions.
        EFFECTIVE_PROFILE_COUNT(effective_num_nonfat_type_checks);
        EFFECTIVE_BOUNDS bounds = {(intptr_t)ptr, (intptr_t)ptr};
        bounds += EFFECTIVE_BOUNDS_NEG_DELTA_DELTA;
        return bounds;
    }
    void *base = lowfat_base(ptr);

    // If the pointer is a lowfat-allocated heap pointer,
    // try looking it up in the cache
    if (lowfat_is_heap_ptr(ptr))
    {
        uint64_t hash = EFFECTIVE_CACHE_HASH(ptr, ptr);
        EFFECTIVE_CACHE_ENTRY *effective_cache_line =
            effective_cache[hash & EFFECTIVE_CACHE_MASK];
        bool is_cached = false;
        EFFECTIVE_BOUNDS cached_bounds;
        size_t num_used = 0;
        for (size_t idx = 0; idx < EFFECTIVE_CACHE_LINE_SIZE; ++idx)
        {
            EFFECTIVE_CACHE_ENTRY *cache_entry =
                &effective_cache_line[idx];
            // Cache hit
            // TODO: use bit manipulation to speed this up
            if (cache_entry->is_used
                & (cache_entry->ptr == ptr)
                & (cache_entry->u == u))
            {
                EFFECTIVE_COUNT(effective_cache_hit);
                EFFECTIVE_DEBUG(
                    "effective_type_check: "
                    "ptr %p -> cache line #%llu, cache hit @ %p\n",
                    ptr, hash & EFFECTIVE_CACHE_MASK, cache_entry);
                is_cached = true;
                cache_entry->last_used = 0;
                cached_bounds = cache_entry->bounds;
            }
            ++cache_entry->last_used;
            num_used += cache_entry->is_used;
        }
        if (is_cached)
        {
            return cached_bounds;
        }
        EFFECTIVE_COUNT(effective_cache_miss);
        if (num_used != EFFECTIVE_CACHE_LINE_SIZE)
        {
            EFFECTIVE_COUNT(effective_cache_cold_miss);
        }
    }

    // Get the object meta-data and calculate the allocation bounds.
    EFFECTIVE_META *meta = (EFFECTIVE_META *)base;
    base = (void *)(meta + 1);
    const EFFECTIVE_TYPE *t = meta->type;
    EFFECTIVE_BOUNDS bases = {(intptr_t)base, (intptr_t)base};
    EFFECTIVE_BOUNDS sizes = {0, meta->size};
    EFFECTIVE_BOUNDS bounds = bases + sizes;
    if (EFFECTIVE_UNLIKELY(t == NULL))
        t = &EFFECTIVE_TYPE_FREE;

    // Calculate and normalize the `offset'. 
    size_t offset = (uint8_t *)ptr - (uint8_t *)base;
    if (offset >= t->size)
    {
        // The `offset' is >= sizeof(T).  Thus `ptr' may be pointing to an
        // element in an array of T.  Alternatively, `ptr' may be pointing to
        // a FAM at the end of T.  Either way, the offset is normalized here.
        EFFECTIVE_BOUNDS adjust = {t->offset_fam, 0};
        offset -= t->size;
        unsigned __int128 tmp = (unsigned __int128)offset;
        tmp *= (unsigned __int128)t->magic;
        idx = (size_t)(tmp >> EFFECTIVE_RADIX);
        offset -= idx * t->size_fam;
        bounds += adjust;
        offset += t->offset_fam;
        effective_type_prefetch();
    }

    EFFECTIVE_DEBUG("effective_type_check(%p, %s, %s (%+zd)) = ", ptr,
        u->info->name, t->info->name, (ssize_t)offset);

    // The following test is equivalent to (offset == 0 && t == u) but with
    // one less jmp instruction:
    if (EFFECTIVE_LIKELY(((t->hash ^ u->hash) | offset) == 0))
    {
        // FAST PATH: Handling of a common special case:
        // - The type `u' matches the allocation type `t'.
        // - The normalized offset is zero.
        EFFECTIVE_DEBUG("%zd..%zd (fast path)\n", bounds[0]-(intptr_t)ptr,
            bounds[1]-(intptr_t)ptr);
        EFFECTIVE_PROFILE_COUNT(effective_num_fast_type_checks);
        effective_cache_insert(ptr, u, bounds);
        return bounds;
    }

    // SLOW PATH: Calculate the hash value for the layout lookup:
    EFFECTIVE_PROFILE_COUNT(effective_num_slow_type_checks);
    EFFECTIVE_BOUNDS ptrs = {(intptr_t)ptr, (intptr_t)ptr};
    uint64_t hval = EFFECTIVE_HASH(t->hash2, u->hash, offset);

    // Probe the layout.  The compiler pass ensures that the number of
    // probes is limited for each query, i.e., that we will hit an
    // EFFECTIVE_ENTRY_EMPTY_HASH within reasonable time.
    idx = hval & t->mask;
    register const EFFECTIVE_ENTRY *entry = t->layout + idx;

    // Look for `u' directly:
    if (entry->hash == hval)
    {
match_found: {}
        EFFECTIVE_BOUNDS offsets = entry->bounds;
        bounds = effective_bounds_narrow(ptrs + offsets, bounds);
        EFFECTIVE_DEBUG("%zd..%zd [%p..%p] (slow path)\n",
            bounds[0]-ptrs[0], bounds[1]-ptrs[1], (void *)bounds[0],
            (void *)bounds[1]);
        effective_cache_insert(ptr, u, bounds);
        return bounds;
    }
    else if (entry->hash != EFFECTIVE_ENTRY_EMPTY_HASH)
    {
        entry++;
        while (true)
        {
            if (entry->hash == hval)
                goto match_found;
            if (entry->hash == EFFECTIVE_ENTRY_EMPTY_HASH)
                break;
            entry++;
        }
    }

    // Search for a coercion of `u', e.g. from (T *) to (void *):
    hval = EFFECTIVE_HASH(t->hash2, u->next, offset);
    idx = hval & t->mask;
    entry = t->layout + idx;
    while (true)
    {
        if (entry->hash == hval)
            goto match_found;
        if (entry->hash == EFFECTIVE_ENTRY_EMPTY_HASH)
            break;
        entry++;
    }

    // Search for (char []):
    hval = EFFECTIVE_HASH(t->hash2, EFFECTIVE_TYPE_INT8.hash, offset);
    idx = hval & t->mask;
    entry = t->layout + idx;
    while (true)
    {
        if (entry->hash == hval)
            goto match_found;
        if (entry->hash == EFFECTIVE_ENTRY_EMPTY_HASH)
            break;
        entry++;
    }

    // The probe failed; this must be a type-error.  Handle it here.
    // Note: we use `ptrs[0]' inplace of `ptr' to reduce register pressure.
	effective_type_error(u, t, (void *)ptrs[0], offset,
        __builtin_return_address(0));
    bounds = ptrs + EFFECTIVE_BOUNDS_NEG_DELTA_DELTA;
    EFFECTIVE_DEBUG("%zd..%zd (type error)\n", bounds[0], bounds[1]);
    return bounds;
}

void effective_cache_insert(const void *ptr,
    const EFFECTIVE_TYPE *u, EFFECTIVE_BOUNDS bounds)
{
    // Much harder to keep track of stack pointers since
    // stack deallocation is implicit.
    // For convenience we only keep track of heap pointers.
    // (And possibly globals...)
    if (!lowfat_is_heap_ptr(ptr))
    {
        return;
    }

    uint64_t hash = EFFECTIVE_CACHE_HASH(ptr, ptr);
    EFFECTIVE_CACHE_ENTRY *effective_cache_line =
        effective_cache[hash & EFFECTIVE_CACHE_MASK];
    EFFECTIVE_CACHE_ENTRY *evict_entry = &effective_cache_line[0];
    bool is_inserted = false;
    for (size_t idx = 0; idx < EFFECTIVE_CACHE_LINE_SIZE & !is_inserted; ++idx)
    {
        EFFECTIVE_CACHE_ENTRY *entry =
            &effective_cache_line[idx];
        if (!entry->is_used)
        {
            // Insert cache entry
            EFFECTIVE_DEBUG(
                "effective_cache_insert: "
                "ptr %p -> cache line #%llu, found empty entry @ %p\n",
                ptr, hash & EFFECTIVE_CACHE_MASK, entry);
            entry->is_used = 1;
            entry->last_used = 1;
            entry->ptr = ptr;
            entry->u = u;
            entry->bounds = bounds;
            is_inserted = true;
        }
        if (evict_entry->last_used < entry->last_used)
        {
            EFFECTIVE_DEBUG(
                "effective_cache_insert: "
                "ptr %p -> cache line #%llu, found older entry @ %p"
                " [%llu vs %llu]\n",
                ptr, hash & EFFECTIVE_CACHE_MASK, entry,
                entry->last_used, evict_entry->last_used);
            evict_entry = entry;
        }
    }
    if (!is_inserted)
    {
            // Evict oldest cache entry
            EFFECTIVE_DEBUG(
                "effective_cache_insert: "
                "ptr %p -> cache line #%llu, evicting entry @ %p\n",
                ptr, hash & EFFECTIVE_CACHE_MASK, evict_entry);
            evict_entry->is_used = 1;
            evict_entry->last_used = 1;
            evict_entry->ptr = ptr;
            evict_entry->u = u;
            evict_entry->bounds = bounds;
    }
}

/*
 * When we free() a lowfat region, invalidate all entries where
 * ptr falls within the lowfat region.
 */
void effective_cache_invalidate(const void *base)
{
    // TODO: try using hash(base) as the row index instead of hash(ptr)
    for (size_t line_idx = 0; line_idx < EFFECTIVE_CACHE_NUM_LINES; ++line_idx)
    {
        for (size_t idx = 0; idx < EFFECTIVE_CACHE_LINE_SIZE; ++idx)
        {
            EFFECTIVE_CACHE_ENTRY *entry = &effective_cache[line_idx][idx];
            if (lowfat_base(entry->ptr) == base)
            {
                entry->is_used = 0;
            }
        }
    }
}

/*
 * Same as `effective_type_check' except specialized for the case where
 * u=(char[]).  Here the whole object will always be matched, except
 * in the case of free memory.
 */
EFFECTIVE_HOT EFFECTIVE_BOUNDS effective_get_bounds(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    if (idx > EFFECTIVE_LOWFAT_NUM_REGIONS_LIMIT || _LOWFAT_MAGICS[idx] == 0)
    {
        EFFECTIVE_PROFILE_COUNT(effective_num_nonfat_type_checks);
        EFFECTIVE_BOUNDS bounds = {(intptr_t)ptr, (intptr_t)ptr};
        return bounds + EFFECTIVE_BOUNDS_NEG_DELTA_DELTA;
    }

    EFFECTIVE_PROFILE_COUNT(effective_num_char_type_checks);
    void *base = lowfat_base(ptr);

    EFFECTIVE_META *meta = (EFFECTIVE_META *)base;
    base = (void *)(meta + 1);
    EFFECTIVE_BOUNDS bases = {(intptr_t)base, (intptr_t)base};
    const EFFECTIVE_TYPE *t = meta->type;
    if (EFFECTIVE_UNLIKELY(t == NULL))
    {
        size_t offset = (uint8_t *)ptr - (uint8_t *)base -
            sizeof(EFFECTIVE_META);
        effective_type_error(&EFFECTIVE_TYPE_INT8, &EFFECTIVE_TYPE_FREE, ptr,
            offset, __builtin_return_address(0));
        return bases + EFFECTIVE_BOUNDS_NEG_DELTA_DELTA;
    }
    base = (void *)(meta + 1);
    EFFECTIVE_BOUNDS sizes = {0, meta->size};
    EFFECTIVE_BOUNDS bounds = bases + sizes;
    EFFECTIVE_DEBUG("effective_get_bounds(%p) = %zd..%zd\n", ptr,
        bounds[0]-(intptr_t)ptr, bounds[1]-(intptr_t)ptr);
    return bounds;
}

/*
 * Perform a bounds check.  Normally this operation is inlined.
 */
EFFECTIVE_HOT void effective_bounds_check(EFFECTIVE_BOUNDS bounds0,
    const void *ptr, intptr_t lb, intptr_t ub)
{
    EFFECTIVE_DEBUG("effective_bounds_check(%p, %zd..%zd) [%zd..%zd]\n",
        ptr, (void *)bounds0[0] - ptr, (void *)bounds0[1] - ptr, lb, ub);
    EFFECTIVE_PROFILE_COUNT(effective_num_bounds_checks);
    EFFECTIVE_BOUNDS ptrs  = {(intptr_t)ptr, (intptr_t)ptr};
    EFFECTIVE_BOUNDS sizes = {lb+1, ub};
    EFFECTIVE_BOUNDS bounds = bounds0 - sizes;
    EFFECTIVE_BOUNDS cmp = (ptrs > bounds);
    int mask = __builtin_ia32_pmovmskb128(cmp);
    if (EFFECTIVE_UNLIKELY(mask != 0x00FF))
    {
        size_t size = sizes[1] - sizes[0] + 1;
        effective_bounds_error(bounds0, ptr, size);
    }
}

