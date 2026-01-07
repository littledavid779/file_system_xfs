// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_dir2.h"
#include "xfs_ialloc.h"
#include "xfs_alloc.h"
#include "xfs_rtalloc.h"
#include "xfs_bmap.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_error.h"
#include "xfs_quota.h"
#include "xfs_fsops.h"
#include "xfs_icache.h"
#include "xfs_sysfs.h"
#include "xfs_rmap_btree.h"
#include "xfs_refcount_btree.h"
#include "xfs_reflink.h"
#include "xfs_extent_busy.h"
#include "xfs_health.h"
#include "xfs_trace.h"
#include "xfs_ag.h"
#include "scrub/stats.h"
#include <linux/xarray.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>


// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/blkdev.h>
// #include <linux/uio.h>

// #include "xfs_file.c"

static DEFINE_MUTEX(xfs_uuid_table_mutex);
static int xfs_uuid_table_size;
static uuid_t *xfs_uuid_table;
// static void init_my_memory_cache(size_t size);
// static void free_and_flush_memory_cache(void);
#ifdef XXFS
#include <linux/gfp.h>
#include <linux/numa.h>

void *memorycache = NULL;
int *blade_page_bitmap = NULL;
spinlock_t *bitmap_lock = NULL;
spinlock_t *blade_page_lock = NULL;
atomic_t *SSD_task_num = NULL;
atomic_t *ready_blade_page_num = NULL;
EXPORT_SYMBOL_GPL(ready_blade_page_num);
atomic_t *unready_blade_page_num = NULL;
EXPORT_SYMBOL_GPL(unready_blade_page_num);
spinlock_t *flush_queue_lock = NULL;
spinlock_t *readssd_queue_lock = NULL;
unsigned short *myxa_val = NULL;
struct xarray **myxa = NULL;
struct task_struct **thread=NULL;
atomic64_t page_used_size;
FlushIOInfo *flush_io_info = NULL;
ReadSSDIOInfo *readssd_io_info = NULL;
void** write_iter_dio_buf = NULL;
BOOL* write_iter_dio_buf_used = NULL;
spinlock_t write_iter_dio_buf_lock;
long long **static_range_query_result = NULL;
io_request** static_blade_io = NULL;
BOOL* static_range_query_result_used = NULL;
BOOL* static_blade_io_used = NULL;
spinlock_t static_range_query_result_lock;
spinlock_t static_blade_io_lock;
ssize_t *blg;
int blg_ed = 0;
spinlock_t blg_lock;
size_t max_blade_page_num = 0;
size_t max_blade_page_io_num = 0;
size_t max_dio_buf_len = 0;
size_t max_range_query_result_num = 0;
size_t max_read_blade_io_num = 0;
size_t *xarray_hash_code_table = NULL;
size_t dio_write_opt_num = 0;
size_t dio_write_page_num = 0;
size_t max_using_page_num = 0;
size_t using_page_num = 0;
size_t sum_buffered_read_request_len = 0;
size_t sum_buffered_read_success_len = 0;
spinlock_t *file_xarray_lock;
struct blade_page_meta *allpage_meta = NULL;
EXPORT_SYMBOL_GPL(allpage_meta);
struct blade_page_data *allpage_data = NULL;
void* flush_buf = NULL;
void* readssd_buf = NULL;
int* flush_thread_work = NULL;
void* no_maganification_read_buf = NULL;

atomic64_t flush_write_blocked;
atomic64_t flush_read_blocked;
size_t print_kernel_state_opt = 0;
ssize_t write_iter_opt = 0;

struct timespec64 last_real_io_time, now_time, mount_time;
struct timespec64 first_rw_time, flush_end_time;

size_t flush_real_times;
size_t readssd_real_times;
ssize_t sum_copy_from_user_bytes;
ssize_t sum_failed_copy_from_user_bytes;
ssize_t sum_write_bytes,sum_read_bytes;

int fsync_cnt = 0;

#ifdef BOTH_ENDS_ALLOC
spinlock_t top_alloc_lock;
spinlock_t bottom_alloc_lock;
size_t top_blade_page_pos = 0;
size_t bottom_blade_page_pos = 0;
#endif

#ifdef CALCULATE_PER4K
struct blade_page_4k *allpage_4k = NULL;
ssize_t used_page_4k_num = 0;
ssize_t full_page_4k_num = 0;
ssize_t *used_page_4k_num_array = NULL;
ssize_t *full_page_4k_num_array = NULL;
#endif

#ifdef CALCULATE_STORAGE_PERCENT
ssize_t sum_storage_bytes = 0;
ssize_t sum_storage_bytes_include_delete = 0; 
ssize_t *sum_storage_bytes_array = NULL;
ssize_t *sum_storage_bytes_include_delete_array = NULL;
ssize_t *sum_write_bytes_array = NULL;
#endif

struct xarray *file_inode_xa = NULL;
// FlushIOInfo *flush_io_info2 = NULL;

//维护数据结构快速确定满块
// ------------------------------------------ 循环队列 Circular Queue ---------------------------------------------------
/* 结构体声明，见 xfs_mount.h
#define MAX_CIRCULAR_QUEUE 10000000 // 循环队列的最大长度
typedef struct {
	int queue[MAX_CIRCULAR_QUEUE]; // 存储队列的数组
	int front; // 队头
	int rear; // 队尾
} CircularQueue;
*/
CircularQueue **flush_circular_queue = NULL;
CircularQueue **readssd_circular_queue = NULL;
// 初始化循环队列
void CircularQueue_init(CircularQueue *q) {
	for(int i = 0; i < MAX_CIRCULAR_QUEUE; i++) {
		q->queue[i].pageid = 0;
		q->queue[i].xaid = 0;
	}
	q->front = 0;
	q->rear = 0;
}
// 判断循环队列是否为空
int CircularQueue_isEmpty(CircularQueue *q) {
	if(q->front == q->rear) return 1;
	return 0;
}
// 判断循环队列是否已满
int CircularQueue_isFull(CircularQueue *q) {
	return (q->rear + 1) % MAX_CIRCULAR_QUEUE == q->front;
}
// 循环队列入队
void CircularQueue_push(CircularQueue *q, int push_pageid, int push_xaid) {
	if (CircularQueue_isFull(q)) {
		printk("[CircurlarQueue PUSH]: ERROR. The Circular Queue is full.\n");
		return;
	}
	q->queue[q->rear].pageid = push_pageid;
	q->queue[q->rear].xaid = push_xaid;
	q->rear = (q->rear + 1) % MAX_CIRCULAR_QUEUE;
}
// 循环队列出队(返回队首)
Queue_Info CircularQueue_pop(CircularQueue *q) {
	if (CircularQueue_isEmpty(q)) {
		printk("[CircularQueue POP]: The Circular Queue is empty.\n");
		return (Queue_Info){-1,-1};
	}
	Queue_Info value = q->queue[q->front];
	q->front = (q->front + 1) % MAX_CIRCULAR_QUEUE;
	return value;
}
// 打印循环队列
void CircularQueue_print(CircularQueue *q) {
	if (CircularQueue_isEmpty(q)) {
		printk("[CirCularQueue PRINTINFO]: The Circular Queue is empty.\n");
		return;
	}
	printk("[CircularQueue PRINTINFO]: length=%d, front=%d, rear=%d, ", CircularQueue_length(q), q->front, q->rear);
	int i = q->front;
	while (i != q->rear) {
		printk(KERN_CONT "{%d,%d}", q->queue[i].pageid, q->queue[i].xaid);
		i = (i + 1) % MAX_CIRCULAR_QUEUE;
	}
}
// 获取循环队列的长度
int CircularQueue_length(CircularQueue *q) {
	return (q->rear - q->front + MAX_CIRCULAR_QUEUE) % MAX_CIRCULAR_QUEUE;
}
// 清空循环队列
void CircularQueue_clear(CircularQueue *q) {
	q->front = q->rear = 0;
}
// ------------------------------------------ 循环队列 Circular Queue End ---------------------------------------------------
#endif




void
xfs_uuid_table_free(void)
{
	if (xfs_uuid_table_size == 0)
		return;
	kmem_free(xfs_uuid_table);
	xfs_uuid_table = NULL;
	xfs_uuid_table_size = 0;
}

/*
 * See if the UUID is unique among mounted XFS filesystems.
 * Mount fails if UUID is nil or a FS with the same UUID is already mounted.
 */
STATIC int
xfs_uuid_mount(
	struct xfs_mount	*mp)
{
	uuid_t			*uuid = &mp->m_sb.sb_uuid;
	int			hole, i;

	/* Publish UUID in struct super_block */
	uuid_copy(&mp->m_super->s_uuid, uuid);

	if (xfs_has_nouuid(mp))
		return 0;

	if (uuid_is_null(uuid)) {
		xfs_warn(mp, "Filesystem has null UUID - can't mount");
		return -EINVAL;
	}

	mutex_lock(&xfs_uuid_table_mutex);
	for (i = 0, hole = -1; i < xfs_uuid_table_size; i++) {
		if (uuid_is_null(&xfs_uuid_table[i])) {
			hole = i;
			continue;
		}
		if (uuid_equal(uuid, &xfs_uuid_table[i]))
			goto out_duplicate;
	}

	if (hole < 0) {
		xfs_uuid_table = krealloc(xfs_uuid_table,
			(xfs_uuid_table_size + 1) * sizeof(*xfs_uuid_table),
			GFP_KERNEL | __GFP_NOFAIL);
		hole = xfs_uuid_table_size++;
	}
	xfs_uuid_table[hole] = *uuid;
	mutex_unlock(&xfs_uuid_table_mutex);

	return 0;

 out_duplicate:
	mutex_unlock(&xfs_uuid_table_mutex);
	xfs_warn(mp, "Filesystem has duplicate UUID %pU - can't mount", uuid);
	return -EINVAL;
}

STATIC void
xfs_uuid_unmount(
	struct xfs_mount	*mp)
{
	uuid_t			*uuid = &mp->m_sb.sb_uuid;
	int			i;

	if (xfs_has_nouuid(mp))
		return;

	mutex_lock(&xfs_uuid_table_mutex);
	for (i = 0; i < xfs_uuid_table_size; i++) {
		if (uuid_is_null(&xfs_uuid_table[i]))
			continue;
		if (!uuid_equal(uuid, &xfs_uuid_table[i]))
			continue;
		memset(&xfs_uuid_table[i], 0, sizeof(uuid_t));
		break;
	}
	ASSERT(i < xfs_uuid_table_size);
	mutex_unlock(&xfs_uuid_table_mutex);
}

/*
 * Check size of device based on the (data/realtime) block count.
 * Note: this check is used by the growfs code as well as mount.
 */
int
xfs_sb_validate_fsb_count(
	xfs_sb_t	*sbp,
	uint64_t	nblocks)
{
	ASSERT(PAGE_SHIFT >= sbp->sb_blocklog);
	ASSERT(sbp->sb_blocklog >= BBSHIFT);

	/* Limited by ULONG_MAX of page cache index */
	if (nblocks >> (PAGE_SHIFT - sbp->sb_blocklog) > ULONG_MAX)
		return -EFBIG;
	return 0;
}

/*
 * xfs_readsb
 *
 * Does the initial read of the superblock.
 */
int
xfs_readsb(
	struct xfs_mount *mp,
	int		flags)
{
	unsigned int	sector_size;
	struct xfs_buf	*bp;
	struct xfs_sb	*sbp = &mp->m_sb;
	int		error;
	int		loud = !(flags & XFS_MFSI_QUIET);
	const struct xfs_buf_ops *buf_ops;

	ASSERT(mp->m_sb_bp == NULL);
	ASSERT(mp->m_ddev_targp != NULL);

	/*
	 * For the initial read, we must guess at the sector
	 * size based on the block device.  It's enough to
	 * get the sb_sectsize out of the superblock and
	 * then reread with the proper length.
	 * We don't verify it yet, because it may not be complete.
	 */
	sector_size = xfs_getsize_buftarg(mp->m_ddev_targp);
	buf_ops = NULL;

	/*
	 * Allocate a (locked) buffer to hold the superblock. This will be kept
	 * around at all times to optimize access to the superblock. Therefore,
	 * set XBF_NO_IOACCT to make sure it doesn't hold the buftarg count
	 * elevated.
	 */
reread:
	error = xfs_buf_read_uncached(mp->m_ddev_targp, XFS_SB_DADDR,
				      BTOBB(sector_size), XBF_NO_IOACCT, &bp,
				      buf_ops);
	if (error) {
		if (loud)
			xfs_warn(mp, "SB validate failed with error %d.", error);
		/* bad CRC means corrupted metadata */
		if (error == -EFSBADCRC)
			error = -EFSCORRUPTED;
		return error;
	}

	/*
	 * Initialize the mount structure from the superblock.
	 */
	xfs_sb_from_disk(sbp, bp->b_addr);

	/*
	 * If we haven't validated the superblock, do so now before we try
	 * to check the sector size and reread the superblock appropriately.
	 */
	if (sbp->sb_magicnum != XFS_SB_MAGIC) {
		if (loud)
			xfs_warn(mp, "Invalid superblock magic number");
		error = -EINVAL;
		goto release_buf;
	}

	/*
	 * We must be able to do sector-sized and sector-aligned IO.
	 */
	if (sector_size > sbp->sb_sectsize) {
		if (loud)
			xfs_warn(mp, "device supports %u byte sectors (not %u)",
				sector_size, sbp->sb_sectsize);
		error = -ENOSYS;
		goto release_buf;
	}

	if (buf_ops == NULL) {
		/*
		 * Re-read the superblock so the buffer is correctly sized,
		 * and properly verified.
		 */
		xfs_buf_relse(bp);
		sector_size = sbp->sb_sectsize;
		buf_ops = loud ? &xfs_sb_buf_ops : &xfs_sb_quiet_buf_ops;
		goto reread;
	}

	mp->m_features |= xfs_sb_version_to_features(sbp);
	xfs_reinit_percpu_counters(mp);

	/* no need to be quiet anymore, so reset the buf ops */
	bp->b_ops = &xfs_sb_buf_ops;

	mp->m_sb_bp = bp;
	xfs_buf_unlock(bp);
	return 0;

release_buf:
	xfs_buf_relse(bp);
	return error;
}

/*
 * If the sunit/swidth change would move the precomputed root inode value, we
 * must reject the ondisk change because repair will stumble over that.
 * However, we allow the mount to proceed because we never rejected this
 * combination before.  Returns true to update the sb, false otherwise.
 */
static inline int
xfs_check_new_dalign(
	struct xfs_mount	*mp,
	int			new_dalign,
	bool			*update_sb)
{
	struct xfs_sb		*sbp = &mp->m_sb;
	xfs_ino_t		calc_ino;

	calc_ino = xfs_ialloc_calc_rootino(mp, new_dalign);
	trace_xfs_check_new_dalign(mp, new_dalign, calc_ino);

	if (sbp->sb_rootino == calc_ino) {
		*update_sb = true;
		return 0;
	}

	xfs_warn(mp,
"Cannot change stripe alignment; would require moving root inode.");

	/*
	 * XXX: Next time we add a new incompat feature, this should start
	 * returning -EINVAL to fail the mount.  Until then, spit out a warning
	 * that we're ignoring the administrator's instructions.
	 */
	xfs_warn(mp, "Skipping superblock stripe alignment update.");
	*update_sb = false;
	return 0;
}

/*
 * If we were provided with new sunit/swidth values as mount options, make sure
 * that they pass basic alignment and superblock feature checks, and convert
 * them into the same units (FSB) that everything else expects.  This step
 * /must/ be done before computing the inode geometry.
 */
STATIC int
xfs_validate_new_dalign(
	struct xfs_mount	*mp)
{
	if (mp->m_dalign == 0)
		return 0;

	/*
	 * If stripe unit and stripe width are not multiples
	 * of the fs blocksize turn off alignment.
	 */
	if ((BBTOB(mp->m_dalign) & mp->m_blockmask) ||
	    (BBTOB(mp->m_swidth) & mp->m_blockmask)) {
		xfs_warn(mp,
	"alignment check failed: sunit/swidth vs. blocksize(%d)",
			mp->m_sb.sb_blocksize);
		return -EINVAL;
	}

	/*
	 * Convert the stripe unit and width to FSBs.
	 */
	mp->m_dalign = XFS_BB_TO_FSBT(mp, mp->m_dalign);
	if (mp->m_dalign && (mp->m_sb.sb_agblocks % mp->m_dalign)) {
		xfs_warn(mp,
	"alignment check failed: sunit/swidth vs. agsize(%d)",
			mp->m_sb.sb_agblocks);
		return -EINVAL;
	}

	if (!mp->m_dalign) {
		xfs_warn(mp,
	"alignment check failed: sunit(%d) less than bsize(%d)",
			mp->m_dalign, mp->m_sb.sb_blocksize);
		return -EINVAL;
	}

	mp->m_swidth = XFS_BB_TO_FSBT(mp, mp->m_swidth);

	if (!xfs_has_dalign(mp)) {
		xfs_warn(mp,
"cannot change alignment: superblock does not support data alignment");
		return -EINVAL;
	}

	return 0;
}

/* Update alignment values based on mount options and sb values. */
STATIC int
xfs_update_alignment(
	struct xfs_mount	*mp)
{
	struct xfs_sb		*sbp = &mp->m_sb;

	if (mp->m_dalign) {
		bool		update_sb;
		int		error;

		if (sbp->sb_unit == mp->m_dalign &&
		    sbp->sb_width == mp->m_swidth)
			return 0;

		error = xfs_check_new_dalign(mp, mp->m_dalign, &update_sb);
		if (error || !update_sb)
			return error;

		sbp->sb_unit = mp->m_dalign;
		sbp->sb_width = mp->m_swidth;
		mp->m_update_sb = true;
	} else if (!xfs_has_noalign(mp) && xfs_has_dalign(mp)) {
		mp->m_dalign = sbp->sb_unit;
		mp->m_swidth = sbp->sb_width;
	}

	return 0;
}

/*
 * precalculate the low space thresholds for dynamic speculative preallocation.
 */
void
xfs_set_low_space_thresholds(
	struct xfs_mount	*mp)
{
	uint64_t		dblocks = mp->m_sb.sb_dblocks;
	uint64_t		rtexts = mp->m_sb.sb_rextents;
	int			i;

	do_div(dblocks, 100);
	do_div(rtexts, 100);

	for (i = 0; i < XFS_LOWSP_MAX; i++) {
		mp->m_low_space[i] = dblocks * (i + 1);
		mp->m_low_rtexts[i] = rtexts * (i + 1);
	}
}

/*
 * Check that the data (and log if separate) is an ok size.
 */
STATIC int
xfs_check_sizes(
	struct xfs_mount *mp)
{
	struct xfs_buf	*bp;
	xfs_daddr_t	d;
	int		error;

	d = (xfs_daddr_t)XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks);
	if (XFS_BB_TO_FSB(mp, d) != mp->m_sb.sb_dblocks) {
		xfs_warn(mp, "filesystem size mismatch detected");
		return -EFBIG;
	}
	error = xfs_buf_read_uncached(mp->m_ddev_targp,
					d - XFS_FSS_TO_BB(mp, 1),
					XFS_FSS_TO_BB(mp, 1), 0, &bp, NULL);
	if (error) {
		xfs_warn(mp, "last sector read failed");
		return error;
	}
	xfs_buf_relse(bp);

	if (mp->m_logdev_targp == mp->m_ddev_targp)
		return 0;

	d = (xfs_daddr_t)XFS_FSB_TO_BB(mp, mp->m_sb.sb_logblocks);
	if (XFS_BB_TO_FSB(mp, d) != mp->m_sb.sb_logblocks) {
		xfs_warn(mp, "log size mismatch detected");
		return -EFBIG;
	}
	error = xfs_buf_read_uncached(mp->m_logdev_targp,
					d - XFS_FSB_TO_BB(mp, 1),
					XFS_FSB_TO_BB(mp, 1), 0, &bp, NULL);
	if (error) {
		xfs_warn(mp, "log device read failed");
		return error;
	}
	xfs_buf_relse(bp);
	return 0;
}

/*
 * Clear the quotaflags in memory and in the superblock.
 */
int
xfs_mount_reset_sbqflags(
	struct xfs_mount	*mp)
{
	mp->m_qflags = 0;

	/* It is OK to look at sb_qflags in the mount path without m_sb_lock. */
	if (mp->m_sb.sb_qflags == 0)
		return 0;
	spin_lock(&mp->m_sb_lock);
	mp->m_sb.sb_qflags = 0;
	spin_unlock(&mp->m_sb_lock);

	if (!xfs_fs_writable(mp, SB_FREEZE_WRITE))
		return 0;

	return xfs_sync_sb(mp, false);
}

uint64_t
xfs_default_resblks(xfs_mount_t *mp)
{
	uint64_t resblks;

	/*
	 * We default to 5% or 8192 fsbs of space reserved, whichever is
	 * smaller.  This is intended to cover concurrent allocation
	 * transactions when we initially hit enospc. These each require a 4
	 * block reservation. Hence by default we cover roughly 2000 concurrent
	 * allocation reservations.
	 */
	resblks = mp->m_sb.sb_dblocks;
	do_div(resblks, 20);
	resblks = min_t(uint64_t, resblks, 8192);
	return resblks;
}

/* Ensure the summary counts are correct. */
STATIC int
xfs_check_summary_counts(
	struct xfs_mount	*mp)
{
	int			error = 0;

	/*
	 * The AG0 superblock verifier rejects in-progress filesystems,
	 * so we should never see the flag set this far into mounting.
	 */
	if (mp->m_sb.sb_inprogress) {
		xfs_err(mp, "sb_inprogress set after log recovery??");
		WARN_ON(1);
		return -EFSCORRUPTED;
	}

	/*
	 * Now the log is mounted, we know if it was an unclean shutdown or
	 * not. If it was, with the first phase of recovery has completed, we
	 * have consistent AG blocks on disk. We have not recovered EFIs yet,
	 * but they are recovered transactionally in the second recovery phase
	 * later.
	 *
	 * If the log was clean when we mounted, we can check the summary
	 * counters.  If any of them are obviously incorrect, we can recompute
	 * them from the AGF headers in the next step.
	 */
	if (xfs_is_clean(mp) &&
	    (mp->m_sb.sb_fdblocks > mp->m_sb.sb_dblocks ||
	     !xfs_verify_icount(mp, mp->m_sb.sb_icount) ||
	     mp->m_sb.sb_ifree > mp->m_sb.sb_icount))
		xfs_fs_mark_sick(mp, XFS_SICK_FS_COUNTERS);

	/*
	 * We can safely re-initialise incore superblock counters from the
	 * per-ag data. These may not be correct if the filesystem was not
	 * cleanly unmounted, so we waited for recovery to finish before doing
	 * this.
	 *
	 * If the filesystem was cleanly unmounted or the previous check did
	 * not flag anything weird, then we can trust the values in the
	 * superblock to be correct and we don't need to do anything here.
	 * Otherwise, recalculate the summary counters.
	 */
	if ((xfs_has_lazysbcount(mp) && !xfs_is_clean(mp)) ||
	    xfs_fs_has_sickness(mp, XFS_SICK_FS_COUNTERS)) {
		error = xfs_initialize_perag_data(mp, mp->m_sb.sb_agcount);
		if (error)
			return error;
	}

	/*
	 * Older kernels misused sb_frextents to reflect both incore
	 * reservations made by running transactions and the actual count of
	 * free rt extents in the ondisk metadata.  Transactions committed
	 * during runtime can therefore contain a superblock update that
	 * undercounts the number of free rt extents tracked in the rt bitmap.
	 * A clean unmount record will have the correct frextents value since
	 * there can be no other transactions running at that point.
	 *
	 * If we're mounting the rt volume after recovering the log, recompute
	 * frextents from the rtbitmap file to fix the inconsistency.
	 */
	if (xfs_has_realtime(mp) && !xfs_is_clean(mp)) {
		error = xfs_rtalloc_reinit_frextents(mp);
		if (error)
			return error;
	}

	return 0;
}

static void
xfs_unmount_check(
	struct xfs_mount	*mp)
{
	if (xfs_is_shutdown(mp))
		return;

	if (percpu_counter_sum(&mp->m_ifree) >
			percpu_counter_sum(&mp->m_icount)) {
		xfs_alert(mp, "ifree/icount mismatch at unmount");
		xfs_fs_mark_sick(mp, XFS_SICK_FS_COUNTERS);
	}
}

/*
 * Flush and reclaim dirty inodes in preparation for unmount. Inodes and
 * internal inode structures can be sitting in the CIL and AIL at this point,
 * so we need to unpin them, write them back and/or reclaim them before unmount
 * can proceed.  In other words, callers are required to have inactivated all
 * inodes.
 *
 * An inode cluster that has been freed can have its buffer still pinned in
 * memory because the transaction is still sitting in a iclog. The stale inodes
 * on that buffer will be pinned to the buffer until the transaction hits the
 * disk and the callbacks run. Pushing the AIL will skip the stale inodes and
 * may never see the pinned buffer, so nothing will push out the iclog and
 * unpin the buffer.
 *
 * Hence we need to force the log to unpin everything first. However, log
 * forces don't wait for the discards they issue to complete, so we have to
 * explicitly wait for them to complete here as well.
 *
 * Then we can tell the world we are unmounting so that error handling knows
 * that the filesystem is going away and we should error out anything that we
 * have been retrying in the background.  This will prevent never-ending
 * retries in AIL pushing from hanging the unmount.
 *
 * Finally, we can push the AIL to clean all the remaining dirty objects, then
 * reclaim the remaining inodes that are still in memory at this point in time.
 */
static void
xfs_unmount_flush_inodes(
	struct xfs_mount	*mp)
{
	xfs_log_force(mp, XFS_LOG_SYNC);
	xfs_extent_busy_wait_all(mp);
	flush_workqueue(xfs_discard_wq);

	set_bit(XFS_OPSTATE_UNMOUNTING, &mp->m_opstate);

	xfs_ail_push_all_sync(mp->m_ail);
	xfs_inodegc_stop(mp);
	cancel_delayed_work_sync(&mp->m_reclaim_work);
	xfs_reclaim_inodes(mp);
	xfs_health_unmount(mp);
}

static void
xfs_mount_setup_inode_geom(
	struct xfs_mount	*mp)
{
	struct xfs_ino_geometry *igeo = M_IGEO(mp);

	igeo->attr_fork_offset = xfs_bmap_compute_attr_offset(mp);
	ASSERT(igeo->attr_fork_offset < XFS_LITINO(mp));

	xfs_ialloc_setup_geometry(mp);
}

/* Compute maximum possible height for per-AG btree types for this fs. */
static inline void
xfs_agbtree_compute_maxlevels(
	struct xfs_mount	*mp)
{
	unsigned int		levels;

	levels = max(mp->m_alloc_maxlevels, M_IGEO(mp)->inobt_maxlevels);
	levels = max(levels, mp->m_rmap_maxlevels);
	mp->m_agbtree_maxlevels = max(levels, mp->m_refc_maxlevels);
}


#ifdef XXFS

#ifndef VMALLOCCTRL
#define VMALLOCCTRL
#define vmalloc(x) vmalloc_node((x), 0)

int blade_page_pos=0;
void init_my_blade_bitmap(void){
	blade_page_bitmap = vmalloc(sizeof(int) * (MemoryCacheSize / (sizeof(struct blade_page))));
#ifdef USING_LOCK
	blade_page_lock = vmalloc(sizeof(spinlock_t) * (MemoryCacheSize / sizeof(struct blade_page)));
	bitmap_lock = vmalloc(sizeof(spinlock_t) * 32);
#endif
	// memset(0,blade_page_bitmap,sizeof(blade_page_bitmap));
	for(int i = 0;i < (MemoryCacheSize / sizeof(struct blade_page)); i++){
		blade_page_bitmap[i] = 0;
#ifdef USING_LOCK
		spin_lock_init(&blade_page_lock[i]);
#endif
	}
	for(int i = 0;i < 32;i++){
#ifdef USING_LOCK
		spin_lock_init(&bitmap_lock[i]);
#endif
	}
	blade_page_pos = 0;
	
#ifdef BOTH_ENDS_ALLOC
	spin_lock_init(&top_alloc_lock);
	spin_lock_init(&bottom_alloc_lock);
	top_blade_page_pos = 0;
	bottom_blade_page_pos = (MemoryCacheSize / sizeof(struct blade_page)) - 1;
#endif

	ASSERT(blade_page_bitmap);
	return;
}


void init_my_memory_cache(size_t size)
{
	// init_my_memory_cache(20ll*1024*1024*1024);
	
	memorycache = vzalloc(size); // vzalloc 申请内存,并初始化为0
	// 初始化 memorycache
	// for(size_t i = 0; i < size; i++){
	// 	*((char *)memorycache + i) = 0;
	// }
	atomic64_set(&page_used_size, 0);

	// 初始化 allpage
	int allpage_size = size / (sizeof(struct blade_page_meta) + sizeof(struct blade_page_data));

	if(allpage_meta == NULL) allpage_meta = memorycache;
	if(allpage_data == NULL) allpage_data = memorycache + allpage_size * sizeof(struct blade_page_meta);

	printk("[IN MOUNTS. INIT MY MEMORY CACHE]: sizeof(struct blade_page_meta) = %ld, expected size = %ld\n", sizeof(struct blade_page_meta), 1ll * 1024);
	printk("[IN MOUNTS. INIT MY MEMORY CACHE]: sizeof(struct blade_page_data) = %ld, expected size = %ld\n", sizeof(struct blade_page_data), 256ll * 1024);
	printk("[IN MOUNTS. INIT MY MEMORY CACHE]: allpage_size = %ld\n", allpage_size);
	// for(int i = 0; i < allpage_size; i++){
		// allpage[i].num = 0;
		// allpage[i].FLBid = -1;
	// 	// 初始化 pos 数组和 len 数组
	// // 	for(int j = 0; j < 127; j++){
	// // 		allpage[i].pos[j] = 0;
	// // 		allpage[i].len[j] = 0;
	// }

	// }
	// int cpu_node = 0;
	// // write_iter_dio_buf = vmalloc_node(cpu_node, sizeof(void *) * WriteIterDIOBufNum);
	// write_iter_dio_buf = vmalloc_node(sizeof(void *) * WriteIterDIOBufNum, cpu_node);
	// if(write_iter_dio_buf == NULL){
	// 	printk("[INIT MY MEMORY CACHE]: vmalloc_node write_iter_dio_buf failed.\n");
	//     write_iter_dio_buf = vmalloc(sizeof(void *) * WriteIterDIOBufNum);
	// 	for(int i = 0; i < WriteIterDIOBufNum; i++){
	// 		write_iter_dio_buf[i] = vmalloc(WriteIterDIOBufSize);
	// 	}
	// }
	// else {
	// 	// printk("[INIT MY MEMORY CACHE]: vmalloc_node write_iter_dio_buf success.\n");
	// 	for(int i = 0; i < WriteIterDIOBufNum; i++){
	// 		write_iter_dio_buf[i] = vmalloc_node(WriteIterDIOBufSize, cpu_node);
	// 		if(write_iter_dio_buf[i] == NULL){
	// 			printk("[INIT MY MEMORY CACHE]: vmalloc_node write_iter_dio_buf[%d] failed.\n", i);
	// 			write_iter_dio_buf[i] = vmalloc(WriteIterDIOBufSize);
	// 		}
	// 	}
	// }

	// write_iter_dio_buf = vmalloc(sizeof(void *) * WriteIterDIOBufNum);
	// for(int i = 0;i < WriteIterDIOBufNum;i++){
	// 	struct page *page = alloc_pages(GFP_KERNEL, get_order(WriteIterDIOBufSize));
	// 	if(!page){
	// 		printk("[IN MOUNTS. INIT MY MEMORY CACHE]: alloc_pages %d failed.",i);
	// 		write_iter_dio_buf[i] = vmalloc(WriteIterDIOBufSize);
	// 	}
	// 	else {
	// 		printk("[IN MOUNTS. INIT MY MEMORY CACHE]: alloc_pages %d success.",i);
	// 		write_iter_dio_buf[i] = (void *) page_to_virt(page);
	// 		// __free_pages(page, get_order(WriteIterDIOBufSize));
	// 	}
	// }

	write_iter_opt = 0;

	fsync_cnt = 0;

#ifdef CALCULATE_PER4K
	allpage_4k = vzalloc(sizeof(struct blade_page_4k) * BLADE_PAGE_4K_NUM);
	used_page_4k_num = 0;
	full_page_4k_num = 0;
	used_page_4k_num_array = vzalloc(sizeof(ssize_t) * MAX_CALCULATE_RECORDS);
	full_page_4k_num_array = vzalloc(sizeof(ssize_t) * MAX_CALCULATE_RECORDS);
#endif

#ifdef CALCULATE_STORAGE_PERCENT
	sum_storage_bytes = 0;
	sum_storage_bytes_include_delete = 0;
	sum_storage_bytes_array = vzalloc(sizeof(ssize_t) * MAX_CALCULATE_RECORDS);
	sum_storage_bytes_include_delete_array = vzalloc(sizeof(ssize_t) * MAX_CALCULATE_RECORDS);
	sum_write_bytes_array = vzalloc(sizeof(ssize_t) * MAX_CALCULATE_RECORDS);
#endif


	write_iter_dio_buf = vmalloc(sizeof(void *) * WriteIterDIOBufNum);
	for(int i = 0; i < WriteIterDIOBufNum; i++){
		write_iter_dio_buf[i] = vmalloc(WriteIterDIOBufSize);
	}
	write_iter_dio_buf_used = vmalloc(sizeof(BOOL) * WriteIterDIOBufNum);
	for(int i = 0; i < WriteIterDIOBufNum; i++){
		write_iter_dio_buf_used[i] = FALSE;
	}

	static_range_query_result = vmalloc(USER_THREAD_NUM * sizeof(int *));
	for(int i = 0; i < USER_THREAD_NUM; i++){
		static_range_query_result[i] = vmalloc(sizeof(int) * 1000);
	}
	static_range_query_result_used = vmalloc(sizeof(BOOL) * USER_THREAD_NUM);
	for(int i = 0; i < USER_THREAD_NUM; i++){
		static_range_query_result_used[i] = FALSE;
	}
	
	static_blade_io = vmalloc(USER_THREAD_NUM * sizeof(io_request *));
	for(int i = 0; i < USER_THREAD_NUM; i++){
		static_blade_io[i] = vmalloc(sizeof(io_request) * 1000);
	}
	static_blade_io_used = vmalloc(sizeof(BOOL) * USER_THREAD_NUM);
	for(int i = 0; i < USER_THREAD_NUM; i++){
		static_blade_io_used[i] = FALSE;
	}

	no_maganification_read_buf = vmalloc(NO_MAGANIFICATION_READ_BUF_SIZE);

#ifdef USING_LOCK
	spin_lock_init(&write_iter_dio_buf_lock);
	spin_lock_init(&static_range_query_result_lock);
	spin_lock_init(&static_blade_io_lock);
#endif

	max_blade_page_io_num = 0;
	max_blade_page_num = 0;
	max_dio_buf_len = 0;
	max_range_query_result_num = 0;
	max_read_blade_io_num = 0;
	dio_write_opt_num = 0;
	dio_write_page_num = 0;
	max_using_page_num = 0;
	using_page_num = 0;
	sum_buffered_read_request_len = 0;
	sum_buffered_read_success_len = 0;
	print_kernel_state_opt = 0;
	sum_copy_from_user_bytes = 0;
	sum_failed_copy_from_user_bytes = 0;
	sum_write_bytes = 0;
	sum_read_bytes = 0;



	reset_time(&first_rw_time);
	reset_time(&flush_end_time);

	reset_time(&last_real_io_time);
	reset_time(&now_time);

	return ;
}

void init_my_xarray(void)
{	
	myxa_val = vmalloc(sizeof(short) * XARRAY_SIZE);
	myxa = vmalloc(sizeof(struct xarray *) * XARRAY_SIZE); 
	for(int i = 0; i < XARRAY_SIZE;i++){
		// myxa[i] = vmalloc(sizeof(struct xarray));
		// xa_init(myxa[i]);
		myxa_val[i] = 0;
	}

	xarray_hash_code_table = vmalloc(sizeof(size_t) * XARRAY_SIZE);
	for(int i = 0; i < XARRAY_SIZE;i++){
		xarray_hash_code_table[i] = -1;
	}

	file_inode_xa = vmalloc(sizeof(struct xarray *));
	init_xarray(&file_inode_xa);


	file_xarray_lock = vmalloc(sizeof(spinlock_t) * XARRAY_SIZE);
	for(int i = 0; i < XARRAY_SIZE;i++){
		spin_lock_init(&file_xarray_lock[i]);
	}


	// for(int i = 0;i < 1200;i++){
	// 	init_xarray(&myxa[i]);
	// }



	// blg = vmalloc(sizeof(ssize_t)* 2000);
	// for(int i = 0;i < 2000;i++){
	// 	blg[i] = -1;
	// }
	// spin_lock_init(&blg_lock);

	return ;
}

void init_my_circular_queue(void){
	flush_circular_queue = vmalloc(sizeof(CircularQueue *) * FLUSH_THREAD_NUM); // 申请线程数个循环队列
	for(int i = 0;i < FLUSH_THREAD_NUM;i++){
		flush_circular_queue[i] = vmalloc(sizeof(CircularQueue));
		CircularQueue_init(flush_circular_queue[i]);
		// printk("[CIRCULAR QUEUE INIT]: flush_circular_queue[%d] initialized.\n", i);
	}
	readssd_circular_queue = vmalloc(sizeof(CircularQueue *) * FLUSH_THREAD_NUM); // 申请线程数个循环队列
	for(int i = 0;i < FLUSH_THREAD_NUM;i++){
		readssd_circular_queue[i] = vmalloc(sizeof(CircularQueue));
		CircularQueue_init(readssd_circular_queue[i]);
		// printk("[CIRCULAR QUEUE INIT]: readssd_circular_queue[%d] initialized.\n", i);
	}
	return ;
}






int SSD_IS_BUSY(int id)
{
	int atomic_val = atomic_read(SSD_task_num+id);
	if(atomic_val>=BUSY_THRESHOLD)
		return 1;
	return 0;
}

//ready_blade_page有两个来源
//1是写的时候 慢慢把它填满了 在bio_merge_single_page里面加判定逻辑
//2是xxfs_flushing里面的读取操作

//下刷操作有很多设计空间
//目前先实现原盘下刷


//目前尚不清楚数据被写入的盘号
//需要研究submit_bio的逻辑


// 同一个页可能会被多次插入到 flush_circular_queue 和 readssd_circular_queue 中
// 当处理到某个页时，可能这个页已经不满足下刷或是读取的条件，所以有必要在处理该页时，判断当前页是否满足下刷或是读取的条件

// 判断相应页是否满足下刷条件
BOOL is_blade_page_satisfy_flush_condition(int blade_page_id){
	// 满足以下两个条件，即可下刷
	// 1. 该页还存在于 xarray 中	
	// 2. 该页仍然是满的(暂时忽略)
	BOOL rtn = TRUE;
	spin_lock(&bitmap_lock[0]);
	if(!blade_page_bitmap[blade_page_id]){ // 不满足条件1
		rtn = FALSE;
	}
	spin_unlock(&bitmap_lock[0]);
	if(rtn == FALSE) return FALSE;

	// spin_lock(&blade_page_lock[blade_page_id]);
	// int sumLen = 0;
	// if(allpage == NULL) allpage = memorycache;
	// for(int i = 0; i < allpage[blade_page_id].num;i++){
	// 	sumLen += allpage[blade_page_id].len[i];
	// }
	// if(sumLen != Aligned_Size){ // 不满足条件2
	// 	rtn = 0;
	// }
	// spin_unlock(&blade_page_lock[blade_page_id]);

	return rtn;
}
// 判断相应页是否满足读取条件
BOOL is_blade_page_satisfy_readssd_condition(int blade_page_id){
	// 满足以下两个条件，即可读取
	// 1. 该页还存在于 xarray 中	
	// 2. 该页不是满的(暂时忽略)
	BOOL rtn = TRUE;
	spin_lock(&bitmap_lock[0]);
	if(!blade_page_bitmap[blade_page_id]){ // 不满足条件1
		rtn = FALSE;
	}
	spin_unlock(&bitmap_lock[0]);
	if(rtn == FALSE) return FALSE;

	// spin_lock(&blade_page_lock[blade_page_id]);
	if(allpage_meta[blade_page_id].num == 1 && allpage_meta[blade_page_id].len[0] == Aligned_Size){ // 不满足条件2
		rtn = FALSE;
	}
	// spin_unlock(&blade_page_lock[blade_page_id]);

	return rtn;
}

// 记录当前时间
void set_now_time(struct timespec64 *now){
	ktime_get_real_ts64(now);
}

// 重置时间
void reset_time(struct timespec64 *time){
	time->tv_sec = 0;
	time->tv_nsec = 0;
}

// 判断时间是否为 0
BOOL is_zero_time(struct timespec64 *time){
	if(time->tv_sec == 0 && time->tv_nsec == 0){
		return TRUE;
	}
	return FALSE;
}

// 将纳秒时间 nsec 转换为秒时间, 返回值为 struct timespec64 结构体
struct timespec64 TIME_NSEC_TO_SEC(long long nsec){
	struct timespec64 rtn;
	rtn.tv_sec = nsec / 1000000000;
	rtn.tv_nsec = nsec % 1000000000;
	return rtn;
}

// 将毫秒时间 msec 转换为纳秒时间
long long TIME_MSEC_TO_NSEC(long long msec){
	return msec * 1000000ll;
}

// 将纳秒时间 nsec 转换为毫秒时间
long long TIME_NSEC_TO_MSEC(long long nsec){
	return nsec / 1000000ll;
}

// 计算两个时间的差值，返回值为秒
long long get_time_diff_sec(struct timespec64 *start, struct timespec64 *end){
	return end->tv_sec - start->tv_sec;
}

// 计算两个时间的差值，返回值为纳秒
long long get_time_diff_nsec(struct timespec64 *start, struct timespec64 *end){
	return get_time_diff_sec(start, end) * 1000000000ll + end->tv_nsec - start->tv_nsec;
}

// 打印内核状态
void print_kernel_state(void){
	print_kernel_state_opt += 1;

	set_now_time(&last_real_io_time);
	
	ssize_t dot_num;
	dot_num = (max_blade_page_num * sizeof(struct blade_page) % (1024ll * 1024 * 1024)) == 0 ? 0 : 1;
	// printk("[PRINT KERNEL STATE]: sum_used_blade_page_num = %ld/%ld, sum used %ldGB memory", max_blade_page_num, MemoryCacheSize / sizeof(struct blade_page), max_blade_page_num * sizeof(struct blade_page) / 1024 / 1024 / 1024 + dot_num);
	dot_num = (max_using_page_num * sizeof(struct blade_page) % (1024ll * 1024 * 1024)) == 0 ? 0 : 1;
	printk("[PRINT KERNEL STATE]: print_kernel_state_opt = %ld", print_kernel_state_opt);
	printk("[PRINT KERNEL STATE]: max_used_blade_page_num_at_the_same_time = %ld, used %ldGB memory at the same time", max_using_page_num, max_using_page_num * sizeof(struct blade_page) / 1024 / 1024 / 1024 + dot_num);
	// printk("[PRINT KERNEL STATE]: max_blade_page_io_num = %ld/128", max_blade_page_io_num);

	dot_num = (max_dio_buf_len % (1024ll * 1024)) == 0 ? 0 : 1;
	// printk("[PRINT KERNEL STATE]: max_used_static_dio_buf_len = %ld/%ld, equals %ldMB", max_dio_buf_len, WriteIterDIOBufSize, max_dio_buf_len / 1024 / 1024 + dot_num);
	// printk("[PRINT KERNEL STATE]: max_range_query_result_num = %ld/1000", max_range_query_result_num);
	// printk("[PRINT KERNEL STATE]: max_read_blade_io_num = %ld/1000", max_read_blade_io_num);
	// printk("[PRINT KERNEL STATE]: dio_write_opt_num = %ld, dio_write_page_num = %ld", dio_write_opt_num, dio_write_page_num);
	// printk("[PRINT KERNEL STATE]: sum_buffered_read_request_len = %ld bytes, sum_buffered_read_success_len = %ld bytes", sum_buffered_read_request_len, sum_buffered_read_success_len);
	printk("[PRINT KERNEL STATE]: flush_circular_queue_length = %ld readssd_circular_queue_length = %ld", CircularQueue_length(flush_circular_queue[0]), CircularQueue_length(readssd_circular_queue[0]));
	printk("[PRINT KERNEL STATE]: flush_real_times = %ld readssd_real_times = %ld", flush_real_times, readssd_real_times);
	// 刷新内核日志输出
	printk(" ");
}

// 调用该函数以输出当前时间
void show_time(void) {
    struct timespec64 ts;
    struct tm tm;

    // 获取当前时间
    ktime_get_real_ts64(&ts);
    
    // 将时间转换为具体的年、月、日、时、分、秒
    time64_to_tm(ts.tv_sec, 0, &tm);

    // printk(KERN_INFO "Current time: %04d-%02d-%02d %02d:%02d:%02d\n",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,(tm.tm_hour + 8) % 24, tm.tm_min, tm.tm_sec);
}



// 深拷贝 kiocb 结构体，经测试，kiocb 结构体在 IO 后不会被修改，所以只需要拷贝一次即可
int deep_copy_kiocb(struct kiocb *src, struct kiocb **dst) {
	if(*dst == NULL){
		struct kiocb *new_kiocb;

		// 分配新的 kiocb 结构体
		new_kiocb = vmalloc(sizeof(struct kiocb));
		
		if (!new_kiocb) {
			// printk("Failed to allocate memory for kiocb\n");
			return -ENOMEM;
		}

		// 拷贝普通字段
		new_kiocb->ki_filp = src->ki_filp;
		// printk("[DEEP COPY KIOCB]: ki_filp = %p\n",new_kiocb->ki_filp);
		new_kiocb->ki_pos = src->ki_pos;
		// printk("[DEEP COPY KIOCB]: ki_pos = %lld\n",new_kiocb->ki_pos);
		// ki_complete 固定为 0x0000000000000000
		new_kiocb->ki_complete = src->ki_complete;
		// printk("[DEEP COPY KIOCB]: ki_complete = %p\n",new_kiocb->ki_complete);
		// 写时 ki_flags 为 6，读时 ki_flags 为 0
		new_kiocb->ki_flags = src->ki_flags;
		// printk("[DEEP COPY KIOCB]: ki_flags = %lu\n",new_kiocb->ki_flags);
		// ki_ioprio 固定为 0
		new_kiocb->ki_ioprio = src->ki_ioprio;
		// printk("[DEEP COPY KIOCB]: ki_ioprio = %d\n",new_kiocb->ki_ioprio);

		// 深拷贝 private 字段
		// if (src->private) {
		//     new_kiocb->private = kmemdup(src->private, sizeof(*src->private), GFP_KERNEL);
		//     if (!new_kiocb->private) {
		//         printk("Failed to allocate memory for private data\n");
		//         kfree(new_kiocb);
		//         return -ENOMEM;
		//     }
		// }
		if (src->private) {
			new_kiocb->private = vmalloc(sizeof(*src->private));
			if (!new_kiocb->private) {
				// printk("[DEEP COPY KIOCB]: ERROR. Failed to allocate memory for private data");
				// printk("Failed to allocate memory for private data\n");
				new_kiocb->private = NULL;
				return -ENOMEM;
			}
			memcpy(new_kiocb->private, src->private, sizeof(*src->private));
		}

		// 处理 union 中的字段，假设 src->ki_waitq 或 src->dio_complete 存在
		if (src->ki_flags & IOCB_WAITQ) {
			new_kiocb->ki_waitq = src->ki_waitq;
		}
		if (src->ki_flags & IOCB_DIO_CALLER_COMP) {
			new_kiocb->dio_complete = src->dio_complete;
		}

		// 将新的 kiocb 返回
		*dst = new_kiocb;
	}
	else { // *dst != NULL 
		// 拷贝普通字段
		(*dst)->ki_filp = src->ki_filp;
		// printk("[DEEP COPY KIOCB]: ki_filp = %p\n",(*dst)->ki_filp);
		(*dst)->ki_pos = src->ki_pos;
		// printk("[DEEP COPY KIOCB]: ki_pos = %lld\n",(*dst)->ki_pos);
		// ki_complete 固定为 0x0000000000000000
		(*dst)->ki_complete = src->ki_complete;
		// printk("[DEEP COPY KIOCB]: ki_complete = %p\n",(*dst)->ki_complete);
		// 写时 ki_flags 为 6，读时 ki_flags 为 0
		(*dst)->ki_flags = src->ki_flags;
		// printk("[DEEP COPY KIOCB]: ki_flags = %lu\n",(*dst)->ki_flags);
		// ki_ioprio 固定为 0
		(*dst)->ki_ioprio = src->ki_ioprio;
		// printk("[DEEP COPY KIOCB]: ki_ioprio = %d\n",(*dst)->ki_ioprio);

		if (src->private) {
			// 直接复用原来的内存
			// (*dst)->private = vmalloc(sizeof(*src->private));
			if (!(*dst)->private) {
				// printk("[DEEP COPY KIOCB]: ERROR. Failed to allocate memory for private data");
				(*dst)->private = NULL;
				return -ENOMEM;
			}
			memcpy((*dst)->private, src->private, sizeof(*src->private));
		}

		// 处理 union 中的字段，假设 src->ki_waitq 或 src->dio_complete 存在
		if (src->ki_flags & IOCB_WAITQ) {
			(*dst)->ki_waitq = src->ki_waitq;
		}
		if (src->ki_flags & IOCB_DIO_CALLER_COMP) {
			(*dst)->dio_complete = src->dio_complete;
		}
	}

	return 0;

}

// 深拷贝 iov_iter 结构体, 认为最大 count 长度为 WriteIterDIOBufSize
int deep_copy_iov_iter(const struct iov_iter *src, struct iov_iter **dst,BOOL is_user_copy){
    // 为 dst 分配内存
	if(*dst == NULL){
		*dst = vmalloc(sizeof(struct iov_iter));
		(*dst)->__iov = NULL;
		(*dst)->kvec = NULL;
		(*dst)->bvec = NULL;
		(*dst)->xarray = NULL;
		(*dst)->ubuf = NULL;
	}
    if (!*dst)
        return -ENOMEM;

    // 拷贝基本字段
    (*dst)->iter_type = src->iter_type;
	// printk("[DEEP COPY IOV ITER]: iter_type = %d\n",(*dst)->iter_type);
    (*dst)->nofault = src->nofault;
	// printk("[DEEP COPY IOV ITER]: nofault = %d\n",(*dst)->nofault);
    (*dst)->data_source = src->data_source;
	// printk("[DEEP COPY IOV ITER]: data_source = %d\n",(*dst)->data_source);
    (*dst)->iov_offset = src->iov_offset;
	// printk("[DEEP COPY IOV ITER]: iov_offset = %ld\n",(*dst)->iov_offset);

	// 拷贝 __ubuf_iovec 字段
	(*dst)->__ubuf_iovec = src->__ubuf_iovec;

    // 根据 iter_type 处理联合体中的字段，测试表明，总是 ITER_UBUF 类型
	switch (src->iter_type) {
	case ITER_IOVEC:
		// 为 dst->__iov 分配内存并拷贝数据
		// printk("[DEEP COPY IOV ITER]: ITER_IOVEC\n");
		// (*dst)->__iov = kmalloc(sizeof(struct iovec) * src->count, GFP_KERNEL);
		if(src->__iov == NULL){
			if((*dst)->__iov) vfree((*dst)->__iov);
			(*dst)->__iov = NULL;
		}
		else {
			if((*dst)->__iov == NULL){
				(*dst)->__iov = vmalloc(sizeof(struct iovec) * WriteIterDIOBufSize);
			}
			memcpy((*dst)->__iov, src->__iov, sizeof(struct iovec) * src->count);
		}
		break;

	case ITER_KVEC:
		// 为 dst->kvec 分配内存并拷贝数据
		// printk("[DEEP COPY IOV ITER]: ITER_KVEC\n");
		// (*dst)->kvec = kmalloc(sizeof(struct kvec) * src->count, GFP_KERNEL);
		if(src->kvec == NULL){
			if((*dst)->kvec) vfree((*dst)->kvec);
			(*dst)->kvec = NULL;
		}
		else {
			if((*dst)->kvec == NULL){
				(*dst)->kvec = vmalloc(sizeof(struct kvec) * WriteIterDIOBufSize);
			}
			memcpy((*dst)->kvec, src->kvec, sizeof(struct kvec) * src->count);
		}
		break;

	case ITER_BVEC:
		// 为 dst->bvec 分配内存并拷贝数据
		// printk("[DEEP COPY IOV ITER]: ITER_BVEC\n");
		// (*dst)->bvec = kmalloc(sizeof(struct bio_vec) * src->count, GFP_KERNEL);
		if(src->bvec == NULL){
			if((*dst)->bvec) vfree((*dst)->bvec);
			(*dst)->bvec = NULL;
		}
		else {
			if((*dst)->bvec == NULL){
				(*dst)->bvec = vmalloc(sizeof(struct bio_vec) * WriteIterDIOBufSize);
			}
			memcpy((*dst)->bvec, src->bvec, sizeof(struct bio_vec) * src->count);
		}
		break;

	case ITER_XARRAY:
		// 为 dst->xarray 分配内存并拷贝数据
		// printk("[DEEP COPY IOV ITER]: ITER_XARRAY\n");
		// (*dst)->xarray = kmalloc(sizeof(struct xarray), GFP_KERNEL);
		if(src->xarray == NULL){
			if((*dst)->xarray) vfree((*dst)->xarray);
			(*dst)->xarray = NULL;
		}
		else {
			if((*dst)->xarray == NULL){
				(*dst)->xarray = vmalloc(sizeof(struct xarray));
			}
			memcpy((*dst)->xarray, src->xarray, sizeof(struct xarray));
		}
		break;

	case ITER_UBUF:
		// 为 dst->ubuf 分配内存并拷贝数据
		// printk("[DEEP COPY IOV ITER]: ITER_UBUF\n");
		// printk("src->count = %ld\n",src->count);
		// (*dst)->ubuf = kmalloc(src->count, GFP_KERNEL);
		// if(is_write_opt){ 

		// void *buf = vmalloc(src->count);
		ssize_t copy_from_user_ret = 0;
		if(src->ubuf == NULL){
			if((*dst)->ubuf) vfree((*dst)->ubuf);
			(*dst)->ubuf = NULL;
		}
		else {
			if((*dst)->ubuf == NULL){
				(*dst)->ubuf = vmalloc(WriteIterDIOBufSize);
			}
			// 首次拷贝，拷贝用户空间数据到内核空间(copy_from_user)，之后的拷贝直接拷贝内核空间数据(memcpy)
			if(is_user_copy) copy_from_user_ret = copy_from_user((*dst)->ubuf, src->ubuf, src->count);
			else memcpy((*dst)->ubuf, src->ubuf, src->count);
			// copy_to_user_ret = copy_to_user((*dst)->ubuf, buf, src->count);
		}
		// if(copy_from_user_ret != 0) printk("[DEEP COPY IOV ITER]: copy_from_user failed\n");
		// else printk("[DEEP COPY IOV ITER]: copy_from_user success\n");
			// if(copy_to_user_ret != 0) printk("[DEEP COPY IOV ITER]: copy_to_user failed\n");
			// else printk("[DEEP COPY IOV ITER]: copy_to_user success\n");
		// }
		// else { // read_from_SSD 时，直接拷贝指针即可
		// 	(*dst)->ubuf = src->ubuf;
		// }
		break;

	default:
		// 未知类型
		// printk("[DEEP COPY IOV ITER]: UNKNOWN TYPE\n");
		return -EINVAL;
	}

    // 拷贝其他字段
    (*dst)->count = src->count;
	// printk("[DEEP COPY IOV ITER]: count = %ld\n",(*dst)->count);
    (*dst)->nr_segs = src->nr_segs;
	// printk("[DEEP COPY IOV ITER]: nr_segs = %d\n",(*dst)->nr_segs);
	(*dst)->xarray_start = src->xarray_start;
	// printk("[DEEP COPY IOV ITER]: OK. deep copy iov iter success.\n");


    return 0;
}

// // 根据文件 inode 号和读写类型 IO_type，创建一个新的 kiocb 结构体，相比于 deep_copy_kiocb 深拷贝一个新的 kiocb 结构体，该函数的创建代价更低
// struct kiocb *create_kiocb(struct inode* inode, IO_TYPE IO_type){

// }


void random_buf_info(void *buf, size_t len){
	for(int i = 0; i < len; i++){
		*((char *)buf + i) = ('a') + (i % 26);
	}
}


// 将从 pos 开始，长度为 len 的 allpage_data 中的数据写入到 SSD
BOOL write_to_SSD(BLADE_PAGE_OFFSET allpage_data_pos, BLADE_PAGE_OFFSET allpage_data_len){
	// if(memorycache_len % 1024 != 0){ // 长度不是 1K 的整数倍,不对齐
	// 	printk("[WRITE TO SSD]: ERROR. len is not aligned with 1K.\n");
	// 	return FALSE;
	// }

	// FlushIOInfo *new_flush_io_info = vmalloc(sizeof(FlushIOInfo));
	// new_flush_io_info->iocb = NULL;
	// new_flush_io_info->iter = NULL;

	// 不进行深拷贝的话可能会出现内存损坏问题：Corruption of in-memory data (0x8) detected at xfs_trans_mod_sb+0x21d/0x220 [xxfs]
	// deep_copy_kiocb(flush_io_info->iocb, &(new_flush_io_info->iocb));
	// deep_copy_iov_iter(flush_io_info->iter, &(new_flush_io_info->iter),FALSE);

	// new_flush_io_info->iocb->ki_pos = memorycache_pos;
	// flush_io_info->iter->count = Aligned_Size;

	// 从 allpage_data 中读取数据
	// memcpy(flush_buf, (char *)(allpage_data) + allpage_data_pos, allpage_data_len);

	struct kvec kvec;
	// kvec.iov_base = flush_buf;
	kvec.iov_base = (char *)(allpage_data) + allpage_data_pos;
	kvec.iov_len = allpage_data_len;

	struct iov_iter new_iter;
	// printk("[WRITE TO SSD]: nr_segs = %ld", flush_io_info->iter->nr_segs);

	// iov_iter_kvec(&new_iter, flush_io_info->iter->data_source, &kvec, flush_io_info->iter->nr_segs, kvec.iov_len);
	// flush_io_info->iter->data_source = WRITE;
	// flush_io_info->iter->nr_segs = 1;
	iov_iter_kvec(&new_iter, WRITE, &kvec, 1, kvec.iov_len);


	ssize_t ret = xfs_file_dio_write(flush_io_info->iocb,&new_iter);
	if(ret != Aligned_Size){
		printk("[WRITE TO SSD]: write_to_SSD failed! return ret = %lld.\n", ret);
	}
	else{
		// printk("[WRITE TO SSD]: write_to_SSD successfully! write %lld bytes.\n", ret);
	}

	// vfree(new_flush_io_info->iocb);
	// new_flush_io_info->iocb = NULL;
	// vfree(new_flush_io_info->iter);
	// new_flush_io_info->iter = NULL;

	return ret > 0 ? TRUE : FALSE;
}

// 从 SSD 读取从 pos 开始，长度为 len 的 allpage_data 中的数据，读到的数据存放在 buf 中,返回读取的数据
BOOL read_from_SSD(BLADE_PAGE_OFFSET allpage_data_pos, BLADE_PAGE_OFFSET allpage_data_len){
	// if(memorycache_len % 1024 != 0){ // 长度不是 1K 的整数倍,不对齐
	// 	// printk("[READ FROM SSD]: ERROR. len is not aligned with 1K.\n");
	// 	return FALSE;
	// }

	// ReadSSDIOInfo *new_readssd_io_info = vmalloc(sizeof(ReadSSDIOInfo));
	// new_readssd_io_info->iocb = NULL;
	// new_readssd_io_info->iter = NULL;

	// deep_copy_kiocb(readssd_io_info->iocb, &(new_readssd_io_info->iocb));
	// deep_copy_iov_iter(readssd_io_info->iter, &(new_readssd_io_info->iter),FALSE);

	// new_readssd_io_info->iocb->ki_pos = memorycache_pos;
	// readssd_io_info->iter->count = Aligned_Size;

	// void *buf = vmalloc(allpage_data_len);

	// printk("[BEFORE READ FROM SSD]: ");
	// for(int i = 0;i < 30;i++){
	// 	printk(KERN_CONT "%02x ",*((char *)buf + i));
	// }


	struct kvec kvec;
	kvec.iov_base = readssd_buf;
	kvec.iov_len = allpage_data_len;

	struct iov_iter new_iter;

	// iov_iter_kvec(&new_iter, readssd_io_info->iter->data_source, &kvec, readssd_io_info->iter->nr_segs, kvec.iov_len);
	// readssd_io_info->iter->data_source = READ;
	// readssd_io_info->iter->nr_segs = 1;
	iov_iter_kvec(&new_iter, READ, &kvec, 1, kvec.iov_len);

	// ssize_t ret = xfs_file_buffered_read(readssd_io_info->iocb,&new_iter);
	ssize_t ret = xfs_file_dio_read(readssd_io_info->iocb,&new_iter);
	if(ret != Aligned_Size){
		printk("[READ FROM SSD]: read_from_SSD failed! return ret = %lld.\n", ret);
	}
	else{
		// printk("[READ FROM SSD]: read_from_SSD successfully! read %lld bytes.\n", ret);
	}

	// printk("[AFTER READ FROM SSD]: ");
	// for(int i = 0;i < 30;i++){
	// 	printk(KERN_CONT "%02x ",*((char *)buf + i));
	// }



	// vfree(readssd_io_info->iocb);
	// new_readssd_io_info->iocb = NULL;
	// vfree(readssd_io_info->iter);
	// new_readssd_io_info->iter = NULL;

	return ret > 0 ? TRUE : FALSE;
}



// 线程 threadid 将 blade_page_id 这一页下刷到 SSD 中
void do_flushing(int threadid, int blade_page_id, int xarray_id){
	if(blade_page_id < 0){
		printk("[DO FLUSHING]: ERROR. blade_page_id < 0. blade_page_id = %d", blade_page_id);
		return ;
	}
	spin_lock(&blade_page_lock[blade_page_id]);
	if(is_blade_page_satisfy_flush_condition(blade_page_id) == FALSE){ // 该页当前的状态不满足下刷条件, 直接返回
		// printk("[DO FLUSHING]: threadid = %d, blade_page_id = %d, not satisfy flush condition.\n",threadid,blade_page_id);
		spin_unlock(&blade_page_lock[blade_page_id]);
		return;
	}


	BLADE_PAGE_OFFSET pos = 1ll * blade_page_id * Aligned_Size;
	// size_t pos = 1ll * blade_page_id * (Aligned_Size + Page_Meta_Size);
	BLADE_PAGE_OFFSET len = Aligned_Size;
	// printk("[DO FLUSHING]: threadid = %d, blade_page_id = %d pos = %ld len = %ld\n",threadid,blade_page_id,pos,len);
	// buf : [pos + Meta_Size, pos + Meta_Size + len)


	spin_unlock(&blade_page_lock[blade_page_id]);
	BOOL write_ret = write_to_SSD(pos, len);
	flush_real_times++;
	// printk("[DO_FLUSING]. flush queue length = %ld flush_real_times = %ld", CircularQueue_length(flush_circular_queue[threadid]), flush_real_times);
	spin_lock(&blade_page_lock[blade_page_id]);


	if(blade_page_bitmap[blade_page_id] == 0){
		spin_unlock(&blade_page_lock[blade_page_id]);
		return;
	}

	// TODO : 下刷成功后, 将该页从 xarray 中删除, 并清空该页对应的元数据 allpage_meta
	if(write_ret == TRUE){
		set_now_time(&flush_end_time);
		// delete_in_xarray(myxa[xarray_id], allpage_meta[blade_page_id].user_pageid, xarray_id);	// 从 xarray 中删除该页
		if(blade_page_bitmap[blade_page_id] == 1){
			delete_in_xarray(myxa[xarray_id], allpage_meta[blade_page_id].user_pageid, xarray_id);	// 从 xarray 中删除该页
		}

		spin_lock(&bitmap_lock[0]);
		blade_page_bitmap[blade_page_id] = 0; // 回收该页
		using_page_num--;
		spin_unlock(&bitmap_lock[0]);

		allpage_meta[blade_page_id].num = 0;
	}

	spin_unlock(&blade_page_lock[blade_page_id]);
	// printk("[DO FLUSHING]: successfully clear allpage_meta and blade_page_bitmap.");
}


// 线程 threadid 将 blade_page_id 这一页从 SSD 中读取上来
void do_readssd(int threadid, int blade_page_id,int xarray_id){
	if(blade_page_id < 0){
		printk("[DO FLUSHING]: ERROR. blade_page_id < 0. blade_page_id = %d", blade_page_id);
		return ;
	}
	spin_lock(&blade_page_lock[blade_page_id]);
	if(is_blade_page_satisfy_readssd_condition(blade_page_id) == FALSE){ // 该页当前的状态不满足读取条件, 直接返回
		// printk("[DO FLUSHING]: threadid = %d, blade_page_id = %d, not satisfy readssd condition.\n",threadid,blade_page_id);
		spin_unlock(&blade_page_lock[blade_page_id]);
		return;
	}

	BLADE_PAGE_OFFSET pos = 1ll * blade_page_id * Aligned_Size;
	BLADE_PAGE_OFFSET len = Aligned_Size;

	spin_unlock(&blade_page_lock[blade_page_id]);
	BOOL read_ret = read_from_SSD(pos, len);
	readssd_real_times++;
	spin_lock(&blade_page_lock[blade_page_id]);

	if(blade_page_bitmap[blade_page_id] == 0){
		spin_unlock(&blade_page_lock[blade_page_id]);
		return;
	}

	if(read_ret == TRUE){
		// TODO : 读取成功后, 将该页的数据更新到 allpage_data 中, 并更新该页对应的元数据 allpage_meta, 并将该页插入到 xarray 中(如果该页不在 xarray 中)
		// if(allpage_meta[blade_page_id].num == 0){
		// 	memcpy((char *)allpage_data + pos, (char *)readssd_buf, len);
		// }
		// else {
		// 	BLADE_PAGE_OFFSET start_pos = 0, end_pos = Aligned_Size - 1;
		// 	int cur_blade_io_idx = 0;
		// 	while(cur_blade_io_idx < allpage_meta[blade_page_id].num){
		// 		end_pos = (int)(allpage_meta[blade_page_id].pos[cur_blade_io_idx]) - 1;
		// 		if(start_pos < end_pos){
		// 			memcpy((char *)allpage_data + pos + start_pos, (char *)readssd_buf + start_pos, end_pos - start_pos + 1);
		// 		}
		// 		start_pos = allpage_meta[blade_page_id].pos[cur_blade_io_idx] + allpage_meta[blade_page_id].len[cur_blade_io_idx];
		// 		cur_blade_io_idx++;
		// 	}
		// }

		allpage_meta[blade_page_id].num = 1;
		allpage_meta[blade_page_id].pos[0] = 0;
		allpage_meta[blade_page_id].len[0] = Aligned_Size;

#ifdef CALCULATE_PER4K
		BLADE_PAGE_OFFSET cur_offset = blade_page_id * Aligned_Size;
		while(cur_offset < blade_page_id * Aligned_Size + Aligned_Size){
			ssize_t cur_4k_page_id = cur_offset / Size4K;

			BOOL pre_used, pre_full;
			if(allpage_4k[cur_4k_page_id].num == 0) pre_used = FALSE;
			else pre_used = TRUE;
			if(pre_used == TRUE && allpage_4k[cur_4k_page_id].sumlen == Size4K) pre_full = TRUE;
			else pre_full = FALSE;

			BLADE_PAGE_OFFSET update_pos = cur_offset % Size4K;
			BLADE_PAGE_OFFSET update_len = mymin(Size4K - update_pos, blade_page_id * Aligned_Size + Aligned_Size - cur_offset);

			// printk("cur_4k_page_id = %ld, update_pos = %ld, update_len = %ld, allpage_4k capcity = %lld", cur_4k_page_id, update_pos, update_len, BLADE_PAGE_4K_NUM);

			bio_merge_single_page_4k(cur_4k_page_id, update_pos, update_len);
			if(pre_used == FALSE && allpage_4k[cur_4k_page_id].num > 0){
				used_page_4k_num += 1;
			}
			if(pre_full == FALSE && allpage_4k[cur_4k_page_id].sumlen == Size4K){
				full_page_4k_num += 1;
			}
			cur_offset += update_len;
		}
#endif
	}


	spin_unlock(&blade_page_lock[blade_page_id]);

	// printk("[DO READSSD]: successfully update allpage_data and allpage_meta.");
}

int xxfs_flushing(void *data)
{
	// int threadid = (current->comm)[9] - '0';
	// flush_thread_work[threadid] = 2;
	// return 0;

	int do_num = 0;
	int threadid = (current->comm)[9] - '0';
	flush_thread_work[threadid] = 1;
	// msleep(20000);
	while (!kthread_should_stop()) {
		do_num++;
		int flag = 0;
        /* 执行任务 */
#ifndef ONLY_READSSD
		if(threadid == 0 && !SSD_IS_BUSY(threadid)) //优先下刷
		{
			while(atomic_read(&ready_blade_page_num[0]) > 0){
				// printk("[DO FLUSHING. IN XXFS_FLUSHING]: ready to do flush!");
				// printk("[DO FLUSHING.] ready_blade_page_num = %d", atomic_read(&ready_blade_page_num[threadid]));
				
				//printk("fast look up a ready_blade_page    thread:%d",threadid); //8*1000w循环队列
				// 扫描对应的循环队列
				int goat_blade_page = -1;
				int goat_xaid = -1;
				// printk("[FLUSH CIRCULAR QUEUE INFO]: threadid = %d length = %d\n",threadid,CircularQueue_length(flush_circular_queue[threadid]));
				spin_lock(&flush_queue_lock[0]); // 获取队列锁
				if(CircularQueue_isEmpty(flush_circular_queue[0]) == 0){
					Queue_Info top = CircularQueue_pop(flush_circular_queue[0]);
					goat_blade_page = top.pageid; // 获取队首元素(blade_page_id)
					// printk("[XXFS_FLUSING]: flush queue length = %ld goat_blade_page = %ld", CircularQueue_length(flush_circular_queue[threadid]), goat_blade_page);
					goat_xaid = top.xaid;
				}
				spin_unlock(&flush_queue_lock[0]); // 释放队列锁

				// if(!blade_page_bitmap[cur_blade_page]) continue; // 该 blade_page 不在 xarray 中
				// TODO: 判断当前的 blade_page 是否满足下刷条件
				// 暂时直接下刷

				if(goat_blade_page != -1){
					// atomic_inc(&SSD_task_num[threadid]); //atomic_add(num,&ato); atomic_sub(num,&ato); 
					// printk("send write I/O to SSD %d",threadid);
					int while_num = 0;
					do {
						while_num++;
						if(while_num > 5000){
							break;
						}
						// udelay(20);
						usleep_range(5, 10);
						if(atomic64_read(&flush_write_blocked) == 1){
							// printk("[XXFS_FLUSHING]: do_flush. while_num = %d", while_num);
							do_flushing(threadid, goat_blade_page, goat_xaid);
							atomic64_set(&flush_write_blocked, 0);


							atomic_dec(&ready_blade_page_num[0]);

							flag = 1;
							break;
						}
					} while(atomic64_read(&flush_write_blocked) == 0);

					if(kthread_should_stop()){
						break;
					}
					// atomic_dec(&SSD_task_num[threadid]);
					// atomic64_sub(Aligned_Size, &page_used_size);
				}
				else {
				// 	printk("[DO FLUSHING. IN XXFS_FLUSHING]: goat_blade_page == -1, but ready_blade_page_num > 0.");
					atomic_dec(&ready_blade_page_num[0]);
				}
			}		
		}
#endif
#ifndef ONLY_FLUSH
		if(threadid == 1 && !SSD_IS_BUSY(threadid)){ //读取
		// if(0){
			// int unready_num = atomic_read(&unready_blade_page_num[threadid]);
			// if(unready_num){
			while(atomic_read(&unready_blade_page_num[0]) > 0){
				// printk("[DO FLUSHING.] unready_blade_page_num = %d threadid = %d", atomic_read(&unready_blade_page_num[threadid]), threadid);
				// printk("[DO READSSD. IN XXFS_FLUSHING]: ready to do readssd!");
				// 在空闲时找一个非满的 blade_page，从 SSD 读取数据，变成一个满的页，后续可以下刷
				// if(threadid == 0) printk("fast look up a non_full_blade_page    thread:%d",threadid); //8*1000w循环队列，加unsigned int数组

				// 暂时将所有非满的页都插入进 readssd_circular_queue 中
				int goat_blade_page = -1;
				int goat_xaid = -1;
				// printk("[READSSD CIRCULAR QUEUE INFO]: threadid = %d length = %d\n",threadid,CircularQueue_length(readssd_circular_queue[threadid]));
				spin_lock(&readssd_queue_lock[0]); // 获取队列锁
				// printk("[XXFS_FLUSHING]: get lock!");
				if(CircularQueue_isEmpty(readssd_circular_queue[0]) == 0){
					Queue_Info top = CircularQueue_pop(readssd_circular_queue[0]);
					// printk("[XXFS_FLUSING]: readssd queue length = %ld unready_blade_page_num = %ld page_id = %ld", CircularQueue_length(readssd_circular_queue[threadid]), atomic_read(&unready_blade_page_num[threadid]),top.pageid);
					// printk("[XXFS_FLUSING]. readssd queue length = %ld queue_front = %d queue_rear = %d", CircularQueue_length(readssd_circular_queue[threadid]), readssd_circular_queue[threadid]->front, readssd_circular_queue[threadid]->rear);
					goat_blade_page = top.pageid;
					goat_xaid = top.xaid;
				}
				// printk("[XXFS_FLUSHING]: pre free lock!");
				spin_unlock(&readssd_queue_lock[0]); // 释放队列锁
				// printk("[XXFS_FLUSHING]: free lock!");
				
				if(goat_blade_page != -1){
					// if(threadid == 0){
					// 	if(is_blade_page_satisfy_read_condition(goat_blade_page)){
					// 		// printk("[READ SSD]: threads = %d blade_page_id = %d, successfully read.",threadid,goat_blade_page);
					// 	}
					// 	else{
					// 		// printk("[READ SSD]: threads = %d blade_page_id = %d, but not satisfy the read condition.",threadid,goat_blade_page);
					// 	}
					// }

					// atomic_inc(&SSD_task_num[threadid]);
					// printk("send read I/O to SSD %d",threadid);
					int while_num = 0;
					do {
						while_num++;
						if(while_num > 5000){
							break;
						}
						usleep_range(5, 10);
						if(atomic64_read(&flush_read_blocked) == 1){
							// printk("[XXFS_FLUSHING]: do_readssd. while_num = %d", while_num);
							do_readssd(threadid, goat_blade_page, goat_xaid);
							// printk("[XXFS_FLUSING]: readssd queue length = %ld unready_blade_page_num = %ld pageid = %ld", CircularQueue_length(readssd_circular_queue[threadid]), atomic_read(&unready_blade_page_num[threadid]), goat_blade_page);
							atomic_dec(&unready_blade_page_num[0]);

							// 读取数据后，这个页会变满，需要将该 blade_page_id 插入到 flush_circular_queue 中
							spin_lock(&flush_queue_lock[0]); // 获取队列锁
							atomic_inc(&ready_blade_page_num[0]);
							CircularQueue_push(flush_circular_queue[0], goat_blade_page, goat_xaid);
							spin_unlock(&flush_queue_lock[0]); // 释放队列锁

							atomic64_set(&flush_read_blocked, 0);
							flag = 1;
							break;

							// atomic_dec(&SSD_task_num[threadid]);
						}
					} while(atomic64_read(&flush_read_blocked) == 0);

					// if(kthread_should_stop()){
					// 	break;
					// }
					// atomic_dec(&SSD_task_num[threadid]);
					// printk("clear corresponding page cache    thread:%d",threadid);
				}
				else {
					// printk("[DO READSSD. IN XXFS_FLUSHING]: goat_blade_page == -1, but unready_blade_page_num > 0. unready_blade_page_num = %d", atomic_read(&unready_blade_page_num[threadid]));
					// printk("[XXFS_FLUSING]. readssd queue length = %ld queue_front = %d queue_rear = %d", CircularQueue_length(readssd_circular_queue[threadid]), readssd_circular_queue[threadid]->front, readssd_circular_queue[threadid]->rear);
					atomic_dec(&unready_blade_page_num[0]);
				}
			}
		}
#endif
		if(flag == 0){
			msleep(500); // 休眠时长
		}
		// udelay(5000); // 100us = 0.1ms

		// if(do_num >= 100000){
		// 	break;
		// }
    }
	flush_thread_work[threadid] = 2;
    return 0;

}

void init_my_flushing_thread(void)
{
	thread = vmalloc(sizeof(struct task_struct *)*FLUSH_THREAD_NUM);
	SSD_task_num = vmalloc(sizeof(atomic_t)*FLUSH_THREAD_NUM);
	ready_blade_page_num = vmalloc(sizeof(atomic_t)*FLUSH_THREAD_NUM);
	unready_blade_page_num = vmalloc(sizeof(atomic_t)*FLUSH_THREAD_NUM);
	flush_io_info = vmalloc(sizeof(FlushIOInfo));
	flush_io_info->iocb = NULL;
	flush_io_info->iter = NULL;
	readssd_io_info = vmalloc(sizeof(ReadSSDIOInfo));
	readssd_io_info->iocb = NULL;
	readssd_io_info->iter = NULL;

	flush_buf = vmalloc(Aligned_Size);
	readssd_buf = vmalloc(Aligned_Size);

	flush_thread_work = vmalloc(sizeof(int) *FLUSH_THREAD_NUM);

	flush_real_times = 0;
	readssd_real_times = 0;

	// flush_io_info2 = vmalloc(sizeof(FlushIOInfo));
	// flush_io_info2->iocb = NULL;
	// flush_io_info2->iter = NULL;
#ifdef USING_LOCK
	flush_queue_lock = vmalloc(sizeof(spinlock_t)*FLUSH_THREAD_NUM);
	readssd_queue_lock = vmalloc(sizeof(spinlock_t)*FLUSH_THREAD_NUM);
#endif
	for(int i=0;i<FLUSH_THREAD_NUM;i++)
	{
		flush_thread_work[i] = 0;
		atomic_set(&SSD_task_num[i], 0);
		atomic_set(&ready_blade_page_num[i], 0);
		atomic_set(&unready_blade_page_num[i], 0);
#ifdef USING_LOCK
		spin_lock_init(&flush_queue_lock[i]);
		spin_lock_init(&readssd_queue_lock[i]);
#endif
	} 
#ifdef DOFLUSH
	atomic64_set(&flush_write_blocked,0);
	atomic64_set(&flush_read_blocked,0);

	char *threadname = vmalloc(20);
	strcpy(threadname,"flush_thd0");
	// printk("name = %s\n",threadname);
	//设置SSD_task_num, ready_blade_page_num, 队列
	// printk("[CIRCULAR QUEUE INFO]: init circular_queue[0].\n");
	// CircularQueue_push(circualr_queue[0], 0);
	// CircularQueue_push(circualr_queue[0], 2);
	// CircularQueue_push(circualr_queue[0], 8);
	// CircularQueue_push(circualr_queue[0], 104);
	// CircularQueue_print(circualr_queue[0]);

	for(int i=0;i<FLUSH_THREAD_NUM;i++)
	{
		threadname[9]='0'+i;
		thread[i]=kthread_create(xxfs_flushing, NULL, threadname);
		if(thread[i])
		{
			wake_up_process(thread[i]);
		}
		else 
		{
			printk("error create thread %d\n",i);
		}
	}
	vfree(threadname);
#endif
}

void free_my_flushing_thread(void)
{
	// return 0;
#ifdef DOFLUSH
	for(int i=0;i<FLUSH_THREAD_NUM;i++){
		if(flush_thread_work[i] == 1){
			kthread_stop(thread[i]);
		}
	}
#endif
	vfree(thread);
	thread=NULL;
	vfree(SSD_task_num);
	SSD_task_num=NULL;
	vfree(ready_blade_page_num);
	ready_blade_page_num=NULL;
	vfree(unready_blade_page_num);
	unready_blade_page_num=NULL;
	vfree(flush_buf);
	flush_buf = NULL;
	vfree(readssd_buf);
	readssd_buf = NULL;
#ifdef USING_LOCK
	vfree(flush_queue_lock);
	flush_queue_lock = NULL;
	vfree(readssd_queue_lock);
	readssd_queue_lock = NULL;
	vfree(flush_io_info->iocb);
	flush_io_info->iocb = NULL;
	vfree(flush_io_info->iter);
	flush_io_info->iter = NULL;
	vfree(flush_io_info);
	flush_io_info = NULL;
	vfree(readssd_io_info->iocb);
	readssd_io_info->iocb = NULL;
	vfree(readssd_io_info->iter);
	readssd_io_info->iter = NULL;
	vfree(readssd_io_info);
	readssd_io_info = NULL;
	// vfree(flush_io_info2->iocb);
	// flush_io_info2->iocb = NULL;
	// vfree(flush_io_info2->iter);
	// flush_io_info2->iter = NULL;
	// vfree(flush_io_info2);
	// flush_io_info2 = NULL;
#endif
}

void free_xarray(void)
{
	for (int i = 0; i < XARRAY_SIZE; i++)
	{
		if(myxa_val[i] == 0) continue;

		// void *data;
		// int j;
		// xa_for_each(myxa[i], j, data){
		// 	kfree(data);
		// }
		xa_destroy(myxa[i]);

		vfree(myxa[i]);
		myxa[i]=NULL;
	}

	vfree(xarray_hash_code_table);
	xarray_hash_code_table = NULL;
	
	vfree(myxa_val);
	myxa_val=NULL;

	vfree(myxa);
	myxa = NULL;

	vfree(file_xarray_lock);
	file_xarray_lock = NULL;

	ssize_t record_num = 0;
	unsigned long key;
	void *entry;
	unsigned long min_key = ULONG_MAX;
	unsigned long max_key = 0;
	xa_for_each(file_inode_xa, key, entry){
		if(key < min_key) min_key = key;
		if(key > max_key) max_key = key;
		record_num++;
	}
	printk("[IN UMOUNT. FREE XARRAY]: file inode record num = %ld. min record = %ld, max record = %ld",record_num,min_key,max_key);


	vfree(file_inode_xa);
	file_inode_xa = NULL;

	// vfree(blg);
	// blg = NULL;

	return ;
}


void free_and_flush_memory_cache(void)
{

#ifdef OPEN_PRINTK
	ssize_t dot_num;
#ifdef BOTH_ENDS_ALLOC
	dot_num = (MemoryCacheSize / sizeof(struct blade_page) - bottom_blade_page_pos + top_blade_page_pos ) % (1024ll * 1024 * 1024) == 0 ? 0 : 1;
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: sum_used_blade_page_num = %ld/%ld, sum used %ldGB memory",MemoryCacheSize / sizeof(struct blade_page) - bottom_blade_page_pos + top_blade_page_pos, MemoryCacheSize / sizeof(struct blade_page), (MemoryCacheSize / sizeof(struct blade_page) - bottom_blade_page_pos + top_blade_page_pos) * sizeof(struct blade_page) / 1024 / 1024 / 1024 + dot_num);
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: sum_used_top_blade_page_num = %ld sum_used_bottom_blade_page_num = %ld, extra_middle_blade_page_num = %ld",top_blade_page_pos, MemoryCacheSize / sizeof(struct blade_page) - bottom_blade_page_pos, bottom_blade_page_pos - top_blade_page_pos);
#else
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: sum_write_opt_bytes = %lld bytes, sum_read_opt_bytes = %lld bytes", sum_write_bytes, sum_read_bytes);
	dot_num = (max_blade_page_num * sizeof(struct blade_page) % (1024ll * 1024 * 1024)) == 0 ? 0 : 1;
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: sum_used_blade_page_num = %ld/%ld, sum used %ldGB memory", max_blade_page_num, MemoryCacheSize / sizeof(struct blade_page), max_blade_page_num * sizeof(struct blade_page) / 1024 / 1024 / 1024 + dot_num);
	dot_num = (max_using_page_num * sizeof(struct blade_page) % (1024ll * 1024 * 1024)) == 0 ? 0 : 1;
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: max_used_blade_page_num_at_the_same_time = %ld, used %ldGB memory at the same time", max_using_page_num, max_using_page_num * sizeof(struct blade_page) / 1024 / 1024 / 1024 + dot_num);
#endif
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: max_blade_page_io_num = %ld/128", max_blade_page_io_num);

	dot_num = (max_dio_buf_len % (1024ll * 1024)) == 0 ? 0 : 1;
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: max_used_static_dio_buf_len = %ld/%ld, equals %ldMB", max_dio_buf_len, WriteIterDIOBufSize, max_dio_buf_len / 1024 / 1024 + dot_num);
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: max_range_query_result_num = %ld/1000", max_range_query_result_num);
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: max_read_blade_io_num = %ld/1000", max_read_blade_io_num);
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: dio_write_opt_num = %ld, dio_write_page_num = %ld", dio_write_opt_num, dio_write_page_num);
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: sum_buffered_read_request_len = %ld bytes, sum_buffered_read_success_len = %ld bytes", sum_buffered_read_request_len, sum_buffered_read_success_len);

	struct timespec64 start_to_flush_end_diff_time = TIME_NSEC_TO_SEC(get_time_diff_nsec(&first_rw_time, &flush_end_time));
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: start_to_flush_end_diff_time = %lld.%llds",start_to_flush_end_diff_time.tv_sec,TIME_NSEC_TO_MSEC(start_to_flush_end_diff_time.tv_nsec));
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: sum_copy_from_user_bytes = %lld bytes, sum_failed_copy_from_user_bytes = %lld bytes", sum_copy_from_user_bytes, sum_failed_copy_from_user_bytes);
	printk("[IN UMOUNT. FREE AND FLUSH MEMORY CACHE]: fsync_cnt = %d", fsync_cnt);

#endif





	//flush !!!!!!
	vfree(memorycache);
	memorycache=NULL;
	for(int i = 0;i < WriteIterDIOBufNum;i++){
		vfree(write_iter_dio_buf[i]);
		write_iter_dio_buf[i] = NULL;

	}
	vfree(write_iter_dio_buf);
	write_iter_dio_buf = NULL;
	// for(int i = 0;i < WriteIterDIOBufNum;i++){
	// 	struct page *page = virt_to_page(write_iter_dio_buf[i]);
	// 	if(page){
	// 		__free_pages(page, get_order(WriteIterDIOBufSize));
	// 	}
	// }
	// vfree(write_iter_dio_buf);
	// write_iter_dio_buf = NULL;

	vfree(write_iter_dio_buf_used);
	write_iter_dio_buf_used = NULL;

	for(int i = 0;i < USER_THREAD_NUM;i++){
		vfree(static_range_query_result[i]);
		static_range_query_result[i] = NULL;
	}
	vfree(static_range_query_result);
	static_range_query_result = NULL;
	vfree(static_range_query_result_used);
	static_range_query_result_used = NULL;

	for(int i = 0;i < USER_THREAD_NUM;i++){
		vfree(static_blade_io[i]);
		static_blade_io[i] = NULL;
	}
	vfree(static_blade_io);
	static_blade_io = NULL;
	vfree(static_blade_io_used);
	static_blade_io_used = NULL;

	vfree(no_maganification_read_buf);
	no_maganification_read_buf = NULL;

#ifdef CALCULATE_PER4K
	vfree(allpage_4k);
	allpage_4k = NULL;
	vfree(used_page_4k_num_array);
	used_page_4k_num_array = NULL;
	vfree(full_page_4k_num_array);
	full_page_4k_num_array = NULL;
#endif

#ifdef CALCULATE_STORAGE_PERCENT
	vfree(sum_storage_bytes_array);
	sum_storage_bytes_array = NULL;
	vfree(sum_storage_bytes_include_delete_array);
	sum_storage_bytes_include_delete_array = NULL;
	vfree(sum_write_bytes_array);
	sum_write_bytes_array = NULL;
#endif

	return ;
}


void free_balde_page_bitmap(void){
	vfree(blade_page_bitmap);
	blade_page_bitmap=NULL;
#ifdef USING_LOCK
	vfree(blade_page_lock);
	blade_page_lock = NULL;
	vfree(bitmap_lock);
	bitmap_lock = NULL;
#endif
	return ;
}
void free_circular_queue(void){
	for(int i = 0;i < FLUSH_THREAD_NUM;i++){
		vfree(flush_circular_queue[i]);
		flush_circular_queue[i] = NULL;
		vfree(readssd_circular_queue[i]);
		readssd_circular_queue[i] = NULL;
	}
	vfree(flush_circular_queue);
	vfree(readssd_circular_queue);
	flush_circular_queue = NULL;
	readssd_circular_queue = NULL;
	return ;
}

#endif // #ifndef VMALLOCCTRL

#endif


/*
 * This function does the following on an initial mount of a file system:
 *	- reads the superblock from disk and init the mount struct
 *	- if we're a 32-bit kernel, do a size check on the superblock
 *		so we don't mount terabyte filesystems
 *	- init mount struct realtime fields
 *	- allocate inode hash table for fs
 *	- init directory manager
 *	- perform recovery and init the log manager
 */
int
xfs_mountfs(
	struct xfs_mount	*mp)
{
	struct xfs_sb		*sbp = &(mp->m_sb);
	struct xfs_inode	*rip;
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	uint			quotamount = 0;
	uint			quotaflags = 0;
	int			error = 0;

#ifdef XXFS
	printk("[IN MOUNTS]: in mounting...");
	set_now_time(&mount_time);
#endif

	xfs_sb_mount_common(mp, sbp);

	/*
	 * Check for a mismatched features2 values.  Older kernels read & wrote
	 * into the wrong sb offset for sb_features2 on some platforms due to
	 * xfs_sb_t not being 64bit size aligned when sb_features2 was added,
	 * which made older superblock reading/writing routines swap it as a
	 * 64-bit value.
	 *
	 * For backwards compatibility, we make both slots equal.
	 *
	 * If we detect a mismatched field, we OR the set bits into the existing
	 * features2 field in case it has already been modified; we don't want
	 * to lose any features.  We then update the bad location with the ORed
	 * value so that older kernels will see any features2 flags. The
	 * superblock writeback code ensures the new sb_features2 is copied to
	 * sb_bad_features2 before it is logged or written to disk.
	 */
	if (xfs_sb_has_mismatched_features2(sbp)) {
		xfs_warn(mp, "correcting sb_features alignment problem");
		sbp->sb_features2 |= sbp->sb_bad_features2;
		mp->m_update_sb = true;
	}


	/* always use v2 inodes by default now */
	if (!(mp->m_sb.sb_versionnum & XFS_SB_VERSION_NLINKBIT)) {
		mp->m_sb.sb_versionnum |= XFS_SB_VERSION_NLINKBIT;
		mp->m_features |= XFS_FEAT_NLINK;
		mp->m_update_sb = true;
	}

	/*
	 * If we were given new sunit/swidth options, do some basic validation
	 * checks and convert the incore dalign and swidth values to the
	 * same units (FSB) that everything else uses.  This /must/ happen
	 * before computing the inode geometry.
	 */
	error = xfs_validate_new_dalign(mp);
	if (error)
		goto out;

	xfs_alloc_compute_maxlevels(mp);
	xfs_bmap_compute_maxlevels(mp, XFS_DATA_FORK);
	xfs_bmap_compute_maxlevels(mp, XFS_ATTR_FORK);
	xfs_mount_setup_inode_geom(mp);
	xfs_rmapbt_compute_maxlevels(mp);
	xfs_refcountbt_compute_maxlevels(mp);


#ifdef XXFS
	// if(memorycache == NULL)
	// {
		init_my_memory_cache(MemoryCacheSize);
	// }
	
	// if(blade_page_bitmap == NULL)
	// {
		init_my_blade_bitmap();
	// }	
	 	init_my_xarray();
#ifdef DOFLUSH
		init_my_circular_queue();
		init_my_flushing_thread();
#endif


#endif


	xfs_agbtree_compute_maxlevels(mp);

	/*
	 * Check if sb_agblocks is aligned at stripe boundary.  If sb_agblocks
	 * is NOT aligned turn off m_dalign since allocator alignment is within
	 * an ag, therefore ag has to be aligned at stripe boundary.  Note that
	 * we must compute the free space and rmap btree geometry before doing
	 * this.
	 */
	error = xfs_update_alignment(mp);
	if (error)
		goto out;


	/* enable fail_at_unmount as default */
	mp->m_fail_unmount = true;

	error = xfs_sysfs_init(&mp->m_kobj, &xfs_mp_ktype,
			       NULL, mp->m_super->s_id);
	if (error)
		goto out;

	error = xfs_sysfs_init(&mp->m_stats.xs_kobj, &xfs_stats_ktype,
			       &mp->m_kobj, "stats");
	if (error)
		goto out_remove_sysfs;

	xchk_stats_register(mp->m_scrub_stats, mp->m_debugfs);

	error = xfs_error_sysfs_init(mp);
	if (error)
		goto out_remove_scrub_stats;

	error = xfs_errortag_init(mp);
	if (error)
		goto out_remove_error_sysfs;

	error = xfs_uuid_mount(mp);
	if (error)
		goto out_remove_errortag;


	/*
	 * Update the preferred write size based on the information from the
	 * on-disk superblock.
	 */
	mp->m_allocsize_log =
		max_t(uint32_t, sbp->sb_blocklog, mp->m_allocsize_log);
	mp->m_allocsize_blocks = 1U << (mp->m_allocsize_log - sbp->sb_blocklog);

	/* set the low space thresholds for dynamic preallocation */
	xfs_set_low_space_thresholds(mp);

	/*
	 * If enabled, sparse inode chunk alignment is expected to match the
	 * cluster size. Full inode chunk alignment must match the chunk size,
	 * but that is checked on sb read verification...
	 */
	if (xfs_has_sparseinodes(mp) &&
	    mp->m_sb.sb_spino_align !=
			XFS_B_TO_FSBT(mp, igeo->inode_cluster_size_raw)) {
		xfs_warn(mp,
	"Sparse inode block alignment (%u) must match cluster size (%llu).",
			 mp->m_sb.sb_spino_align,
			 XFS_B_TO_FSBT(mp, igeo->inode_cluster_size_raw));
		error = -EINVAL;
		goto out_remove_uuid;
	}

	/*
	 * Check that the data (and log if separate) is an ok size.
	 */
	error = xfs_check_sizes(mp);
	if (error)
		goto out_remove_uuid;

	/*
	 * Initialize realtime fields in the mount structure
	 */
	error = xfs_rtmount_init(mp);
	if (error) {
		xfs_warn(mp, "RT mount failed");
		goto out_remove_uuid;
	}

	/*
	 *  Copies the low order bits of the timestamp and the randomly
	 *  set "sequence" number out of a UUID.
	 */
	mp->m_fixedfsid[0] =
		(get_unaligned_be16(&sbp->sb_uuid.b[8]) << 16) |
		 get_unaligned_be16(&sbp->sb_uuid.b[4]);
	mp->m_fixedfsid[1] = get_unaligned_be32(&sbp->sb_uuid.b[0]);

	error = xfs_da_mount(mp);
	if (error) {
		xfs_warn(mp, "Failed dir/attr init: %d", error);
		goto out_remove_uuid;
	}

	/*
	 * Initialize the precomputed transaction reservations values.
	 */
	xfs_trans_init(mp);

	/*
	 * Allocate and initialize the per-ag data.
	 */
	error = xfs_initialize_perag(mp, sbp->sb_agcount, mp->m_sb.sb_dblocks,
			&mp->m_maxagi);
	if (error) {
		xfs_warn(mp, "Failed per-ag init: %d", error);
		goto out_free_dir;
	}

	if (XFS_IS_CORRUPT(mp, !sbp->sb_logblocks)) {
		xfs_warn(mp, "no log defined");
		error = -EFSCORRUPTED;
		goto out_free_perag;
	}

	error = xfs_inodegc_register_shrinker(mp);
	if (error)
		goto out_fail_wait;

	/*
	 * Log's mount-time initialization. The first part of recovery can place
	 * some items on the AIL, to be handled when recovery is finished or
	 * cancelled.
	 */
	error = xfs_log_mount(mp, mp->m_logdev_targp,
			      XFS_FSB_TO_DADDR(mp, sbp->sb_logstart),
			      XFS_FSB_TO_BB(mp, sbp->sb_logblocks));
	if (error) {
		xfs_warn(mp, "log mount failed");
		goto out_inodegc_shrinker;
	}



	/* Enable background inode inactivation workers. */
	xfs_inodegc_start(mp);
	xfs_blockgc_start(mp);

	/*
	 * Now that we've recovered any pending superblock feature bit
	 * additions, we can finish setting up the attr2 behaviour for the
	 * mount. The noattr2 option overrides the superblock flag, so only
	 * check the superblock feature flag if the mount option is not set.
	 */
	if (xfs_has_noattr2(mp)) {
		mp->m_features &= ~XFS_FEAT_ATTR2;
	} else if (!xfs_has_attr2(mp) &&
		   (mp->m_sb.sb_features2 & XFS_SB_VERSION2_ATTR2BIT)) {
		mp->m_features |= XFS_FEAT_ATTR2;
	}

	/*
	 * Get and sanity-check the root inode.
	 * Save the pointer to it in the mount structure.
	 */
	error = xfs_iget(mp, NULL, sbp->sb_rootino, XFS_IGET_UNTRUSTED,
			 XFS_ILOCK_EXCL, &rip);
	if (error) {
		xfs_warn(mp,
			"Failed to read root inode 0x%llx, error %d",
			sbp->sb_rootino, -error);
		goto out_log_dealloc;
	}

	ASSERT(rip != NULL);

	if (XFS_IS_CORRUPT(mp, !S_ISDIR(VFS_I(rip)->i_mode))) {
		xfs_warn(mp, "corrupted root inode %llu: not a directory",
			(unsigned long long)rip->i_ino);
		xfs_iunlock(rip, XFS_ILOCK_EXCL);
		error = -EFSCORRUPTED;
		goto out_rele_rip;
	}
	mp->m_rootip = rip;	/* save it */

	xfs_iunlock(rip, XFS_ILOCK_EXCL);

	/*
	 * Initialize realtime inode pointers in the mount structure
	 */
	error = xfs_rtmount_inodes(mp);
	if (error) {
		/*
		 * Free up the root inode.
		 */
		xfs_warn(mp, "failed to read RT inodes");
		goto out_rele_rip;
	}

	/* Make sure the summary counts are ok. */
	error = xfs_check_summary_counts(mp);
	if (error)
		goto out_rtunmount;

	/*
	 * If this is a read-only mount defer the superblock updates until
	 * the next remount into writeable mode.  Otherwise we would never
	 * perform the update e.g. for the root filesystem.
	 */
	if (mp->m_update_sb && !xfs_is_readonly(mp)) {
		error = xfs_sync_sb(mp, false);
		if (error) {
			xfs_warn(mp, "failed to write sb changes");
			goto out_rtunmount;
		}
	}

	/*
	 * Initialise the XFS quota management subsystem for this mount
	 */
	if (XFS_IS_QUOTA_ON(mp)) {
		error = xfs_qm_newmount(mp, &quotamount, &quotaflags);
		if (error)
			goto out_rtunmount;
	} else {
		/*
		 * If a file system had quotas running earlier, but decided to
		 * mount without -o uquota/pquota/gquota options, revoke the
		 * quotachecked license.
		 */
		if (mp->m_sb.sb_qflags & XFS_ALL_QUOTA_ACCT) {
			xfs_notice(mp, "resetting quota flags");
			error = xfs_mount_reset_sbqflags(mp);
			if (error)
				goto out_rtunmount;
		}
	}


	/*
	 * Finish recovering the file system.  This part needed to be delayed
	 * until after the root and real-time bitmap inodes were consistently
	 * read in.  Temporarily create per-AG space reservations for metadata
	 * btree shape changes because space freeing transactions (for inode
	 * inactivation) require the per-AG reservation in lieu of reserving
	 * blocks.
	 */
	error = xfs_fs_reserve_ag_blocks(mp);
	if (error && error == -ENOSPC)
		xfs_warn(mp,
	"ENOSPC reserving per-AG metadata pool, log recovery may fail.");
	error = xfs_log_mount_finish(mp);
	xfs_fs_unreserve_ag_blocks(mp);
	if (error) {
		xfs_warn(mp, "log mount finish failed");
		goto out_rtunmount;
	}

	/*
	 * Now the log is fully replayed, we can transition to full read-only
	 * mode for read-only mounts. This will sync all the metadata and clean
	 * the log so that the recovery we just performed does not have to be
	 * replayed again on the next mount.
	 *
	 * We use the same quiesce mechanism as the rw->ro remount, as they are
	 * semantically identical operations.
	 */
	if (xfs_is_readonly(mp) && !xfs_has_norecovery(mp))
		xfs_log_clean(mp);

	/*
	 * Complete the quota initialisation, post-log-replay component.
	 */
	if (quotamount) {
		ASSERT(mp->m_qflags == 0);
		mp->m_qflags = quotaflags;

		xfs_qm_mount_quotas(mp);
	}

	/*
	 * Now we are mounted, reserve a small amount of unused space for
	 * privileged transactions. This is needed so that transaction
	 * space required for critical operations can dip into this pool
	 * when at ENOSPC. This is needed for operations like create with
	 * attr, unwritten extent conversion at ENOSPC, etc. Data allocations
	 * are not allowed to use this reserved space.
	 *
	 * This may drive us straight to ENOSPC on mount, but that implies
	 * we were already there on the last unmount. Warn if this occurs.
	 */
	if (!xfs_is_readonly(mp)) {
		error = xfs_reserve_blocks(mp, xfs_default_resblks(mp));
		if (error)
			xfs_warn(mp,
	"Unable to allocate reserve blocks. Continuing without reserve pool.");

		/* Reserve AG blocks for future btree expansion. */
		error = xfs_fs_reserve_ag_blocks(mp);
		if (error && error != -ENOSPC)
			goto out_agresv;
	}

#ifdef XXFS
	set_now_time(&now_time);
	struct timespec64 mount_time_diff = TIME_NSEC_TO_SEC(get_time_diff_nsec(&mount_time, &now_time));
	printk("[IN MOUNTS]: mounts OK. mount time = %lld.%llds",mount_time_diff.tv_sec,TIME_NSEC_TO_MSEC(mount_time_diff.tv_nsec));
	// 刷新内核日志输出
	printk(" ");
#endif

	return 0;

 out_agresv:
	xfs_fs_unreserve_ag_blocks(mp);
	xfs_qm_unmount_quotas(mp);
 out_rtunmount:
	xfs_rtunmount_inodes(mp);
 out_rele_rip:
	xfs_irele(rip);
	/* Clean out dquots that might be in memory after quotacheck. */
	xfs_qm_unmount(mp);

	/*
	 * Inactivate all inodes that might still be in memory after a log
	 * intent recovery failure so that reclaim can free them.  Metadata
	 * inodes and the root directory shouldn't need inactivation, but the
	 * mount failed for some reason, so pull down all the state and flee.
	 */
	xfs_inodegc_flush(mp);

	/*
	 * Flush all inode reclamation work and flush the log.
	 * We have to do this /after/ rtunmount and qm_unmount because those
	 * two will have scheduled delayed reclaim for the rt/quota inodes.
	 *
	 * This is slightly different from the unmountfs call sequence
	 * because we could be tearing down a partially set up mount.  In
	 * particular, if log_mount_finish fails we bail out without calling
	 * qm_unmount_quotas and therefore rely on qm_unmount to release the
	 * quota inodes.
	 */
	xfs_unmount_flush_inodes(mp);
 out_log_dealloc:
	xfs_log_mount_cancel(mp);
 out_inodegc_shrinker:
	shrinker_free(mp->m_inodegc_shrinker);
 out_fail_wait:
	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp)
		xfs_buftarg_drain(mp->m_logdev_targp);
	xfs_buftarg_drain(mp->m_ddev_targp);
 out_free_perag:
	xfs_free_perag(mp);
 out_free_dir:
	xfs_da_unmount(mp);
 out_remove_uuid:
	xfs_uuid_unmount(mp);
 out_remove_errortag:
	xfs_errortag_del(mp);
 out_remove_error_sysfs:
	xfs_error_sysfs_del(mp);
 out_remove_scrub_stats:
	xchk_stats_unregister(mp->m_scrub_stats);
	xfs_sysfs_del(&mp->m_stats.xs_kobj);
 out_remove_sysfs:
	xfs_sysfs_del(&mp->m_kobj);
 out:


	return error;
}

/*
 * This flushes out the inodes,dquots and the superblock, unmounts the
 * log and makes sure that incore structures are freed.
 */
void
xfs_unmountfs(
	struct xfs_mount	*mp)
{
	int			error;

	/*
	 * Perform all on-disk metadata updates required to inactivate inodes
	 * that the VFS evicted earlier in the unmount process.  Freeing inodes
	 * and discarding CoW fork preallocations can cause shape changes to
	 * the free inode and refcount btrees, respectively, so we must finish
	 * this before we discard the metadata space reservations.  Metadata
	 * inodes and the root directory do not require inactivation.
	 */
	xfs_inodegc_flush(mp);

	xfs_blockgc_stop(mp);
	xfs_fs_unreserve_ag_blocks(mp);
	xfs_qm_unmount_quotas(mp);
	xfs_rtunmount_inodes(mp);
	xfs_irele(mp->m_rootip);

#ifdef XXFS

#ifdef DOFLUSH
	free_my_flushing_thread();
	free_circular_queue();
#endif
	free_and_flush_memory_cache();
	free_xarray();
	free_balde_page_bitmap();

#endif

	xfs_unmount_flush_inodes(mp);

	xfs_qm_unmount(mp);
	/*
	 * Unreserve any blocks we have so that when we unmount we don't account
	 * the reserved free space as used. This is really only necessary for
	 * lazy superblock counting because it trusts the incore superblock
	 * counters to be absolutely correct on clean unmount.
	 *
	 * We don't bother correcting this elsewhere for lazy superblock
	 * counting because on mount of an unclean filesystem we reconstruct the
	 * correct counter value and this is irrelevant.
	 *
	 * For non-lazy counter filesystems, this doesn't matter at all because
	 * we only every apply deltas to the superblock and hence the incore
	 * value does not matter....
	 */
	error = xfs_reserve_blocks(mp, 0);
	if (error)
		xfs_warn(mp, "Unable to free reserved block pool. "
				"Freespace may not be correct on next mount.");
	xfs_unmount_check(mp);

	xfs_log_unmount(mp);
	xfs_da_unmount(mp);
	xfs_uuid_unmount(mp);

#if defined(DEBUG)
	xfs_errortag_clearall(mp);
#endif
	shrinker_free(mp->m_inodegc_shrinker);
	xfs_free_perag(mp);

	xfs_errortag_del(mp);
	xfs_error_sysfs_del(mp);
	xchk_stats_unregister(mp->m_scrub_stats);
	xfs_sysfs_del(&mp->m_stats.xs_kobj);
	xfs_sysfs_del(&mp->m_kobj);
}

/*
 * Determine whether modifications can proceed. The caller specifies the minimum
 * freeze level for which modifications should not be allowed. This allows
 * certain operations to proceed while the freeze sequence is in progress, if
 * necessary.
 */
bool
xfs_fs_writable(
	struct xfs_mount	*mp,
	int			level)
{
	ASSERT(level > SB_UNFROZEN);
	if ((mp->m_super->s_writers.frozen >= level) ||
	    xfs_is_shutdown(mp) || xfs_is_readonly(mp))
		return false;

	return true;
}

/* Adjust m_fdblocks or m_frextents. */
int
xfs_mod_freecounter(
	struct xfs_mount	*mp,
	struct percpu_counter	*counter,
	int64_t			delta,
	bool			rsvd)
{
	int64_t			lcounter;
	long long		res_used;
	uint64_t		set_aside = 0;
	s32			batch;
	bool			has_resv_pool;

	ASSERT(counter == &mp->m_fdblocks || counter == &mp->m_frextents);
	has_resv_pool = (counter == &mp->m_fdblocks);
	if (rsvd)
		ASSERT(has_resv_pool);

	if (delta > 0) {
		/*
		 * If the reserve pool is depleted, put blocks back into it
		 * first. Most of the time the pool is full.
		 */
		if (likely(!has_resv_pool ||
			   mp->m_resblks == mp->m_resblks_avail)) {
			percpu_counter_add(counter, delta);
			return 0;
		}

		spin_lock(&mp->m_sb_lock);
		res_used = (long long)(mp->m_resblks - mp->m_resblks_avail);

		if (res_used > delta) {
			mp->m_resblks_avail += delta;
		} else {
			delta -= res_used;
			mp->m_resblks_avail = mp->m_resblks;
			percpu_counter_add(counter, delta);
		}
		spin_unlock(&mp->m_sb_lock);
		return 0;
	}

	/*
	 * Taking blocks away, need to be more accurate the closer we
	 * are to zero.
	 *
	 * If the counter has a value of less than 2 * max batch size,
	 * then make everything serialise as we are real close to
	 * ENOSPC.
	 */
	if (__percpu_counter_compare(counter, 2 * XFS_FDBLOCKS_BATCH,
				     XFS_FDBLOCKS_BATCH) < 0)
		batch = 1;
	else
		batch = XFS_FDBLOCKS_BATCH;

	/*
	 * Set aside allocbt blocks because these blocks are tracked as free
	 * space but not available for allocation. Technically this means that a
	 * single reservation cannot consume all remaining free space, but the
	 * ratio of allocbt blocks to usable free blocks should be rather small.
	 * The tradeoff without this is that filesystems that maintain high
	 * perag block reservations can over reserve physical block availability
	 * and fail physical allocation, which leads to much more serious
	 * problems (i.e. transaction abort, pagecache discards, etc.) than
	 * slightly premature -ENOSPC.
	 */
	if (has_resv_pool)
		set_aside = xfs_fdblocks_unavailable(mp);
	percpu_counter_add_batch(counter, delta, batch);
	if (__percpu_counter_compare(counter, set_aside,
				     XFS_FDBLOCKS_BATCH) >= 0) {
		/* we had space! */
		return 0;
	}

	/*
	 * lock up the sb for dipping into reserves before releasing the space
	 * that took us to ENOSPC.
	 */
	spin_lock(&mp->m_sb_lock);
	percpu_counter_add(counter, -delta);
	if (!has_resv_pool || !rsvd)
		goto fdblocks_enospc;

	lcounter = (long long)mp->m_resblks_avail + delta;
	if (lcounter >= 0) {
		mp->m_resblks_avail = lcounter;
		spin_unlock(&mp->m_sb_lock);
		return 0;
	}
	xfs_warn_once(mp,
"Reserve blocks depleted! Consider increasing reserve pool size.");

fdblocks_enospc:
	spin_unlock(&mp->m_sb_lock);
	return -ENOSPC;
}

/*
 * Used to free the superblock along various error paths.
 */
void
xfs_freesb(
	struct xfs_mount	*mp)
{
	struct xfs_buf		*bp = mp->m_sb_bp;

	xfs_buf_lock(bp);
	mp->m_sb_bp = NULL;
	xfs_buf_relse(bp);
}

/*
 * If the underlying (data/log/rt) device is readonly, there are some
 * operations that cannot proceed.
 */
int
xfs_dev_is_read_only(
	struct xfs_mount	*mp,
	char			*message)
{
	if (xfs_readonly_buftarg(mp->m_ddev_targp) ||
	    xfs_readonly_buftarg(mp->m_logdev_targp) ||
	    (mp->m_rtdev_targp && xfs_readonly_buftarg(mp->m_rtdev_targp))) {
		xfs_notice(mp, "%s required on read-only device.", message);
		xfs_notice(mp, "write access unavailable, cannot proceed.");
		return -EROFS;
	}
	return 0;
}

/* Force the summary counters to be recalculated at next mount. */
void
xfs_force_summary_recalc(
	struct xfs_mount	*mp)
{
	if (!xfs_has_lazysbcount(mp))
		return;

	xfs_fs_mark_sick(mp, XFS_SICK_FS_COUNTERS);
}

/*
 * Enable a log incompat feature flag in the primary superblock.  The caller
 * cannot have any other transactions in progress.
 */
int
xfs_add_incompat_log_feature(
	struct xfs_mount	*mp,
	uint32_t		feature)
{
	struct xfs_dsb		*dsb;
	int			error;

	ASSERT(hweight32(feature) == 1);
	ASSERT(!(feature & XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN));

	/*
	 * Force the log to disk and kick the background AIL thread to reduce
	 * the chances that the bwrite will stall waiting for the AIL to unpin
	 * the primary superblock buffer.  This isn't a data integrity
	 * operation, so we don't need a synchronous push.
	 */
	error = xfs_log_force(mp, XFS_LOG_SYNC);
	if (error)
		return error;
	xfs_ail_push_all(mp->m_ail);

	/*
	 * Lock the primary superblock buffer to serialize all callers that
	 * are trying to set feature bits.
	 */
	xfs_buf_lock(mp->m_sb_bp);
	xfs_buf_hold(mp->m_sb_bp);

	if (xfs_is_shutdown(mp)) {
		error = -EIO;
		goto rele;
	}

	if (xfs_sb_has_incompat_log_feature(&mp->m_sb, feature))
		goto rele;

	/*
	 * Write the primary superblock to disk immediately, because we need
	 * the log_incompat bit to be set in the primary super now to protect
	 * the log items that we're going to commit later.
	 */
	dsb = mp->m_sb_bp->b_addr;
	xfs_sb_to_disk(dsb, &mp->m_sb);
	dsb->sb_features_log_incompat |= cpu_to_be32(feature);
	error = xfs_bwrite(mp->m_sb_bp);
	if (error)
		goto shutdown;

	/*
	 * Add the feature bits to the incore superblock before we unlock the
	 * buffer.
	 */
	xfs_sb_add_incompat_log_features(&mp->m_sb, feature);
	xfs_buf_relse(mp->m_sb_bp);

	/* Log the superblock to disk. */
	return xfs_sync_sb(mp, false);
shutdown:
	xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
rele:
	xfs_buf_relse(mp->m_sb_bp);
	return error;
}

/*
 * Clear all the log incompat flags from the superblock.
 *
 * The caller cannot be in a transaction, must ensure that the log does not
 * contain any log items protected by any log incompat bit, and must ensure
 * that there are no other threads that depend on the state of the log incompat
 * feature flags in the primary super.
 *
 * Returns true if the superblock is dirty.
 */
bool
xfs_clear_incompat_log_features(
	struct xfs_mount	*mp)
{
	bool			ret = false;

	if (!xfs_has_crc(mp) ||
	    !xfs_sb_has_incompat_log_feature(&mp->m_sb,
				XFS_SB_FEAT_INCOMPAT_LOG_ALL) ||
	    xfs_is_shutdown(mp))
		return false;

	/*
	 * Update the incore superblock.  We synchronize on the primary super
	 * buffer lock to be consistent with the add function, though at least
	 * in theory this shouldn't be necessary.
	 */
	xfs_buf_lock(mp->m_sb_bp);
	xfs_buf_hold(mp->m_sb_bp);

	if (xfs_sb_has_incompat_log_feature(&mp->m_sb,
				XFS_SB_FEAT_INCOMPAT_LOG_ALL)) {
		xfs_sb_remove_incompat_log_features(&mp->m_sb);
		ret = true;
	}

	xfs_buf_relse(mp->m_sb_bp);
	return ret;
}

/*
 * Update the in-core delayed block counter.
 *
 * We prefer to update the counter without having to take a spinlock for every
 * counter update (i.e. batching).  Each change to delayed allocation
 * reservations can change can easily exceed the default percpu counter
 * batching, so we use a larger batch factor here.
 *
 * Note that we don't currently have any callers requiring fast summation
 * (e.g. percpu_counter_read) so we can use a big batch value here.
 */
#define XFS_DELALLOC_BATCH	(4096)
void
xfs_mod_delalloc(
	struct xfs_mount	*mp,
	int64_t			delta)
{
	percpu_counter_add_batch(&mp->m_delalloc_blks, delta,
			XFS_DELALLOC_BATCH);
}
