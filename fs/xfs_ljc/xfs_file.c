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
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_inode_item.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_ioctl.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_icache.h"
#include "xfs_pnfs.h"
#include "xfs_iomap.h"
#include "xfs_reflink.h"

#include <linux/dax.h>
#include <linux/falloc.h>
#include <linux/backing-dev.h>
#include <linux/mman.h>
#include <linux/fadvise.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
//changed 11.20

#include <linux/ktime.h> 
#include <linux/random.h>
#include "/home/jiachengliu/Desktop/linux-6.9.12/include/asm-generic/access_ok.h"

// #define printk if(0)_printk

static const struct vm_operations_struct xfs_file_vm_ops;
static ssize_t xfs_file_dax_write(struct kiocb *iocb, struct iov_iter *from);
// static ssize_t xfs_file_dio_write(struct kiocb *iocb, struct iov_iter *from);
static ssize_t xfs_file_buffered_write(struct kiocb *iocb, struct iov_iter *from);

/*
 * Decide if the given file range is aligned to the size of the fundamental
 * allocation unit for the file.
 */
static bool
xfs_is_falloc_aligned(
	struct xfs_inode	*ip,
	loff_t			pos,
	long long int		len)
{
	struct xfs_mount	*mp = ip->i_mount;
	uint64_t		mask;

	if (XFS_IS_REALTIME_INODE(ip)) {
		if (!is_power_of_2(mp->m_sb.sb_rextsize)) {
			u64	rextbytes;
			u32	mod;

			rextbytes = XFS_FSB_TO_B(mp, mp->m_sb.sb_rextsize);
			div_u64_rem(pos, rextbytes, &mod);
			if (mod)
				return false;
			div_u64_rem(len, rextbytes, &mod);
			return mod == 0;
		}
		mask = XFS_FSB_TO_B(mp, mp->m_sb.sb_rextsize) - 1;
	} else {
		mask = mp->m_sb.sb_blocksize - 1;
	}

	return !((pos | len) & mask);
}

/*
 * Fsync operations on directories are much simpler than on regular files,
 * as there is no file data to flush, and thus also no need for explicit
 * cache flush operations, and there are no non-transaction metadata updates
 * on directories either.
 */
STATIC int
xfs_dir_fsync(
	struct file		*file,
	loff_t			start,
	loff_t			end,
	int			datasync)
{
	struct xfs_inode	*ip = XFS_I(file->f_mapping->host);

	trace_xfs_dir_fsync(ip);
	return xfs_log_force_inode(ip);
}

static xfs_csn_t
xfs_fsync_seq(
	struct xfs_inode	*ip,
	bool			datasync)
{
	if (!xfs_ipincount(ip))
		return 0;
	if (datasync && !(ip->i_itemp->ili_fsync_fields & ~XFS_ILOG_TIMESTAMP))
		return 0;
	return ip->i_itemp->ili_commit_seq;
}

/*
 * All metadata updates are logged, which means that we just have to flush the
 * log up to the latest LSN that touched the inode.
 *
 * If we have concurrent fsync/fdatasync() calls, we need them to all block on
 * the log force before we clear the ili_fsync_fields field. This ensures that
 * we don't get a racing sync operation that does not wait for the metadata to
 * hit the journal before returning.  If we race with clearing ili_fsync_fields,
 * then all that will happen is the log force will do nothing as the lsn will
 * already be on disk.  We can't race with setting ili_fsync_fields because that
 * is done under XFS_ILOCK_EXCL, and that can't happen because we hold the lock
 * shared until after the ili_fsync_fields is cleared.
 */
static  int
xfs_fsync_flush_log(
	struct xfs_inode	*ip,
	bool			datasync,
	int			*log_flushed)
{
	int			error = 0;
	xfs_csn_t		seq;

	xfs_ilock(ip, XFS_ILOCK_SHARED);
	seq = xfs_fsync_seq(ip, datasync);
	if (seq) {
		error = xfs_log_force_seq(ip->i_mount, seq, XFS_LOG_SYNC,
					  log_flushed);

		spin_lock(&ip->i_itemp->ili_lock);
		ip->i_itemp->ili_fsync_fields = 0;
		spin_unlock(&ip->i_itemp->ili_lock);
	}
	xfs_iunlock(ip, XFS_ILOCK_SHARED);
	return error;
}


#ifdef XXFS
STATIC int
xfs_file_fsync(
	struct file		*file,
	loff_t			start,
	loff_t			end,
	int			datasync)
{
	struct xfs_inode	*ip = XFS_I(file->f_mapping->host);
	struct xfs_mount	*mp = ip->i_mount;
	int			error = 0, err2;
	int			log_flushed = 0;

	trace_xfs_file_fsync(ip);

#ifdef XFS_PRINTK
	printk("fsync /mnt/xfstest/%ld\n", ip->i_ino);
#endif

	fsync_cnt++;

	// unsigned long index;
	// void *entry;
	// int full_page_num = 0, unfull_page_num = 0;
	// ssize_t sum_bytes = 0;
	// size_t xaid = get_hashcode(ip->i_ino);
	// if(myxa_val[xaid] == 1){
	// 	xa_for_each(myxa[xaid], index, entry) {
	// 		if (entry) {
	// 			int nowpage = (int)(unsigned long)entry;
	// 			if(nowpage >= 0){
	// 				int sumlen = 0;
	// 				for(int j = 0;j < allpage_meta[nowpage].num;j++){
	// 					sumlen += allpage_meta[nowpage].len[j];
	// 				}
	// 				if(sumlen == Aligned_Size) full_page_num++;
	// 				else unfull_page_num++;
	// 			}
	// 			else {
	// 				printk("fsync error. nowpage < 0. nowpage = %d", nowpage);
	// 			}
	// 		}
	// 	}
	// }
	// else {
	// 	printk("fsync myxa_val == 0. f_pos = %lld", file->f_pos);
	// }
	// printk("full_page_num = %d, unfull_page_num = %d", full_page_num, unfull_page_num);
	// int sleep_time_us = unfull_page_num * 249 + full_page_num * 86;
	// int sleep_time_us = unfull_page_num * 209 + full_page_num * 72;
	// usleep_range(sleep_time_us, sleep_time_us + 10);

	// error = file_write_and_wait_range(file, start, end);
	// if (error)
	// 	return error;

	if (xfs_is_shutdown(mp))
		return -EIO;

	// xfs_iflags_clear(ip, XFS_ITRUNCATED);

	/*
	 * If we have an RT and/or log subvolume we need to make sure to flush
	 * the write cache the device used for file data first.  This is to
	 * ensure newly written file data make it to disk before logging the new
	 * inode size in case of an extending write.
	 */
	if (XFS_IS_REALTIME_INODE(ip))
		error = blkdev_issue_flush(mp->m_rtdev_targp->bt_bdev);
	else if (mp->m_logdev_targp != mp->m_ddev_targp)
		error = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);

	/*
	 * Any inode that has dirty modifications in the log is pinned.  The
	 * racy check here for a pinned inode will not catch modifications
	 * that happen concurrently to the fsync call, but fsync semantics
	 * only require to sync previously completed I/O.
	 */
	if (xfs_ipincount(ip)) {
		err2 = xfs_fsync_flush_log(ip, datasync, &log_flushed);
		if (err2 && !error)
			error = err2;
	}

	/*
	 * If we only have a single device, and the log force about was
	 * a no-op we might have to flush the data device cache here.
	 * This can only happen for fdatasync/O_DSYNC if we were overwriting
	 * an already allocated file and thus do not have any metadata to
	 * commit.
	 */

	// will do
	if (!log_flushed && !XFS_IS_REALTIME_INODE(ip) &&
	    mp->m_logdev_targp == mp->m_ddev_targp) {
		err2 = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
		if (err2 && !error)
			error = err2;
	}

	return error;
}
#else
STATIC int
xfs_file_fsync(
	struct file		*file,
	loff_t			start,
	loff_t			end,
	int			datasync)
{
	struct xfs_inode	*ip = XFS_I(file->f_mapping->host);
	struct xfs_mount	*mp = ip->i_mount;
	int			error, err2;
	int			log_flushed = 0;

	trace_xfs_file_fsync(ip);

#ifdef XFS_PRINTK
	printk("fsync /mnt/xfstest/%ld\n", ip->i_ino);
#endif

	error = file_write_and_wait_range(file, start, end);
	if (error)
		return error;

	if (xfs_is_shutdown(mp))
		return -EIO;

	xfs_iflags_clear(ip, XFS_ITRUNCATED);

	/*
	 * If we have an RT and/or log subvolume we need to make sure to flush
	 * the write cache the device used for file data first.  This is to
	 * ensure newly written file data make it to disk before logging the new
	 * inode size in case of an extending write.
	 */
	if (XFS_IS_REALTIME_INODE(ip))
		error = blkdev_issue_flush(mp->m_rtdev_targp->bt_bdev);
	else if (mp->m_logdev_targp != mp->m_ddev_targp)
		error = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);

	/*
	 * Any inode that has dirty modifications in the log is pinned.  The
	 * racy check here for a pinned inode will not catch modifications
	 * that happen concurrently to the fsync call, but fsync semantics
	 * only require to sync previously completed I/O.
	 */
	if (xfs_ipincount(ip)) {
		err2 = xfs_fsync_flush_log(ip, datasync, &log_flushed);
		if (err2 && !error)
			error = err2;
	}

	/*
	 * If we only have a single device, and the log force about was
	 * a no-op we might have to flush the data device cache here.
	 * This can only happen for fdatasync/O_DSYNC if we were overwriting
	 * an already allocated file and thus do not have any metadata to
	 * commit.
	 */
	if (!log_flushed && !XFS_IS_REALTIME_INODE(ip) &&
	    mp->m_logdev_targp == mp->m_ddev_targp) {
		err2 = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
		if (err2 && !error)
			error = err2;
	}

	return error;
}
#endif

static int
xfs_ilock_iocb(
	struct kiocb		*iocb,
	unsigned int		lock_mode)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!xfs_ilock_nowait(ip, lock_mode))
			return -EAGAIN;
	} else {
		xfs_ilock(ip, lock_mode);
	}

	return 0;
}

static int
xfs_ilock_iocb_for_write(
	struct kiocb		*iocb,
	unsigned int		*lock_mode)
{
	ssize_t			ret;
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));

	ret = xfs_ilock_iocb(iocb, *lock_mode);
	if (ret)
		return ret;

	if (*lock_mode == XFS_IOLOCK_EXCL)
		return 0;
	if (!xfs_iflags_test(ip, XFS_IREMAPPING))
		return 0;

	xfs_iunlock(ip, *lock_mode);
	*lock_mode = XFS_IOLOCK_EXCL;
	return xfs_ilock_iocb(iocb, *lock_mode);
}

static unsigned int
xfs_ilock_for_write_fault(
	struct xfs_inode	*ip)
{
	/* get a shared lock if no remapping in progress */
	xfs_ilock(ip, XFS_MMAPLOCK_SHARED);
	if (!xfs_iflags_test(ip, XFS_IREMAPPING))
		return XFS_MMAPLOCK_SHARED;

	/* wait for remapping to complete */
	xfs_iunlock(ip, XFS_MMAPLOCK_SHARED);
	xfs_ilock(ip, XFS_MMAPLOCK_EXCL);
	return XFS_MMAPLOCK_EXCL;
}

ssize_t
xfs_file_dio_read(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));
	ssize_t			ret;

	trace_xfs_file_direct_read(iocb, to);

	if (!iov_iter_count(to))
		return 0; /* skip atime */

	file_accessed(iocb->ki_filp);

	ret = xfs_ilock_iocb(iocb, XFS_IOLOCK_SHARED);
	if (ret)
		return ret;
	ret = iomap_dio_rw(iocb, to, &xfs_read_iomap_ops, NULL, 0, NULL, 0);
	xfs_iunlock(ip, XFS_IOLOCK_SHARED);

	return ret;
}

static noinline ssize_t
xfs_file_dax_read(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct xfs_inode	*ip = XFS_I(iocb->ki_filp->f_mapping->host);
	ssize_t			ret = 0;

	trace_xfs_file_dax_read(iocb, to);

	if (!iov_iter_count(to))
		return 0; /* skip atime */

	ret = xfs_ilock_iocb(iocb, XFS_IOLOCK_SHARED);
	if (ret)
		return ret;
	ret = dax_iomap_rw(iocb, to, &xfs_read_iomap_ops);// 直接从持久性内存设备读取数据，并将数据写道应用程序的缓冲区
	xfs_iunlock(ip, XFS_IOLOCK_SHARED);//读后解锁文件

	file_accessed(iocb->ki_filp);//更新访问时间
	return ret;
}

ssize_t
xfs_file_buffered_read(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));
	ssize_t			ret;

	trace_xfs_file_buffered_read(iocb, to);

	ret = xfs_ilock_iocb(iocb, XFS_IOLOCK_SHARED);
	if (ret)
		return ret;
	ret = generic_file_read_iter(iocb, to);
	//generic_file_read_iter是一个通用接口 在这里只使用了其buffered io功能
	//这个函数只需要设置IOCB_DIRECT标志就能实现灵活的IO操作
	xfs_iunlock(ip, XFS_IOLOCK_SHARED);

	return ret;
}

/* 在 xfs_mount.h 中定义
#define Aligned_Size (16ll*1024)
#define Aligned_Shift 14
#define Page_Meta_Size (1*1024)
#define Memory_Size (10ll*1024*1024*1024)
*/
// #define MAX_IO 1000
//#define MAX_RANGES 100
// 



/* 在 xfs_mount.h 中定义
#define MAX_PAGE_UPDATES 16
struct blade_page
{
	unsigned short pos[254];
	unsigned short len[254];
	unsigned short num;
	unsigned short lock; // 0 无锁 1 读锁 2 写锁
	unsigned int FLBid; // file logical block id
	char data[Aligned_Size];
};
*/
// #define USING_LOCK
#ifdef XXFS

int lookup_blade_page(size_t pos)
{
	return 0;
}

inline ssize_t mymin(ssize_t a, ssize_t b)
{
	if(a<b)
		return a;
	return b;
}

inline ssize_t mymax(ssize_t a, ssize_t b)
{
	if(a>b)
		return a;
	return b;
}

inline ssize_t get_random_num(ssize_t L, ssize_t R){
	unsigned long long num;
	get_random_bytes(&num, sizeof(num));
	return num % (R - L + 1) + L;
}

size_t get_hashcode(long value) {
	const unsigned long HASH_MOD = 9999991;
    unsigned long long a = 6364136223846793005ULL;  // 常数，通常选择一个较大的质数
    unsigned long long c = 1;  // 另一个常数
    unsigned long long hash_value = a * value + c;  // 乘法哈希公式
    return hash_value % HASH_MOD;  // 取模操作，确保结果在 [0, 999999] 范围内
}


#define BITMAP_PARTITION ((3000000 / 16) / (Aligned_Size / 16 / 1024))
#ifdef DYNAMIC_PAGE_SIZE
// 根据段号来获取页大小, 每一段按照 256KB，64KB，16KB 来分配
BLADE_PAGE_SIZE_TYPE get_page_size(BLADE_PAGE_OFFSET segment_id){
	if(segment_id % 3 == 0) return Size256K;
	if(segment_id % 3 == 1) return Size64K;
	return Size16K;
}
// 根据段号来获取页的空间大小
BLADE_PAGE_OFFSET get_page_memory_size(BLADE_PAGE_OFFSET segment_id){
	// 一个 blade_page 单元的大小是 16KB + 1KB = 17KB
	if(segment_id % 3 == 0) return 16 * sizeof(struct blade_page); // 256KB
	if(segment_id % 3 == 1) return 4 * sizeof(struct blade_page); // 64KB
	return sizeof(struct blade_page); // 16KB
}

// 先根据 blade_page_pos 来规定这个页的大小, 每一段按照 256KB，64KB，16KB 来分配
int alloc_blade_page(void){
	while(blade_page_bitmap[blade_page_pos]){
		blade_page_pos++;
		// 计算当前页的起始偏移量
		BLADE_PAGE_OFFSET start_offset = blade_page_pos * sizeof(struct blade_page);
		// 计算起始位置位于哪一段
		BLADE_PAGE_OFFSET start_offset_segment_id = start_offset / SEGMENT_SIZE;
		// 根据段号来确定当前页的大小
		BLADE_PAGE_SIZE_TYPE page_size = get_page_memory_size(start_offset_segment_id);
		// 计算当前页的结束位置
		BLADE_PAGE_OFFSET end_offset = start_offset + page_size;
		// 计算结束位置位于哪一段
		BLADE_PAGE_OFFSET end_offset_segment_id = end_offset / SEGMENT_SIZE;
		// 如果当前页的结束位置超过了当前段的大小（跨段），则舍弃这个页号，继续寻找下一个页号，直到找到一个不跨段的页号
		if(start_offset_segment_id != end_offset_segment_id){
			continue;
		}
	}
	blade_page_bitmap[blade_page_pos] = 1;
	// printk("[ALLOC PAGE]: blade_page_pos = %d\n",blade_page_pos);	
#ifdef USING_LOCK
	spin_lock(&blade_page_lock[blade_page_pos]);
#endif
	allpage[blade_page_pos].num = 0;
	allpage[blade_page_pos].FLBid = -1;
	// 根据段号来确定当前页的大小
	allpage[blade_page_pos].page_size = get_page_size(( blade_page_pos * sizeof(struct blade_page) ) / SEGMENT_SIZE);
	// 首页是控制页
	allpage[blade_page_pos].page_type = BLADE_PAGE_TYPE_CONTROL;
	// 根据页的大小，来决定使用多少个 allpage 单元
	if(allpage[blade_page_pos].page_size == Size256K){ // 使用 16 个 allpage 单元
		for(int i = 1; i < 16; i++){ // 后面 15 个单元都是纯数据页
			blade_page_pos++;
			blade_page_bitmap[blade_page_pos] = 1;
			allpage[blade_page_pos].num = 0;
			allpage[blade_page_pos].FLBid = -1;
			allpage[blade_page_pos].page_size = Size256K;
			allpage[blade_page_pos].page_type = BLADE_PAGE_TYPE_DATA;
		}
	}
	else if(allpage[blade_page_pos].page_size == Size64K){ // 使用 4 个 allpage 单元
		for(int i = 1; i < 4; i++){ // 后面 3 个单元都是纯数据页
			blade_page_pos++;
			blade_page_bitmap[blade_page_pos] = 1;
			allpage[blade_page_pos].num = 0;
			allpage[blade_page_pos].FLBid = -1;
			allpage[blade_page_pos].page_size = Size64K;
			allpage[blade_page_pos].page_type = BLADE_PAGE_TYPE_DATA;
		}
	}
	else { // 使用 1 个 allpage 单元
		// do nothing
	}
#ifdef USING_LOCK
	spin_unlock(&blade_page_lock[blade_page_pos]);
#endif
	return blade_page_pos;
}
#elif defined(BOTH_ENDS_ALLOC)
typedef enum {
	TYPE_TOP,
	TYPE_BOTTOM
} ALLOC_TYPE;
int alloc_blade_page(ALLOC_TYPE alloc_type){
	size_t goat_blade_page_pos = 0;
	if(alloc_type == TYPE_TOP){
		while(blade_page_bitmap[top_blade_page_pos]){
			top_blade_page_pos++;
		}
		blade_page_bitmap[top_blade_page_pos] = 1;
		goat_blade_page_pos = top_blade_page_pos;
		if(top_blade_page_pos % 2000 == 0) printk("[BOTH ENDS ALLOC BLADE PAGE]: top_blade_page_pos = %ld\n",top_blade_page_pos);
	}
	else{
		while(blade_page_bitmap[bottom_blade_page_pos]){
			bottom_blade_page_pos--;
		}
		blade_page_bitmap[bottom_blade_page_pos] = 1;
		goat_blade_page_pos = bottom_blade_page_pos;
		if(bottom_blade_page_pos % 2000 == 0) printk("[BOTH ENDS ALLOC BLADE PAGE]: bottom_blade_page_pos = %ld\n",bottom_blade_page_pos);
	}
	return goat_blade_page_pos;
}
#else 
int alloc_blade_page(void){
	// 5G == 20480 blade page 256k
	while(blade_page_bitmap[blade_page_pos]){
		blade_page_pos++;
		// if(blade_page_pos % 10000 == 0) printk("[ALLOC BLADE PAGE]: in while. blade_page_pos = %ld",blade_page_pos);
		if(blade_page_pos + 100 >= MemoryCacheSize / sizeof(struct blade_page) ){
			printk("[ALLOC BLADE PAGE]: blade_page_pos becomes 0");
			blade_page_pos = 0;
			// return 0;
		}
	}


	blade_page_bitmap[blade_page_pos] = 1;
	// allpage[blade_page_pos].num=0;
	// allpage[blade_page_pos].FLBid=-1; 
	// blade_page_bitmap[blade_page_pos] = 1;
	// printk("[ALLOC PAGE]: blade_page_pos = %d\n",blade_page_pos);
// #ifdef USING_LOCK
// 	spin_lock(&blade_page_lock[blade_page_pos]);
// #endif
	allpage_meta[blade_page_pos].num = 0;
	// allpage[blade_page_pos].FLBid=-1; 

	// if(blade_page_pos % 10000 == 0) printk("[ALLOC BLADE PAGE]: simple case. blade_page_pos = %d\n",blade_page_pos);
// #ifdef USING_LOCK
// 	spin_unlock(&blade_page_lock[blade_page_pos]);
// #endif

#ifdef DOFLUSH
	// atomic64_add(Aligned_Size, &page_used_size); // 暂定这么写
#endif
	max_blade_page_num = mymax(max_blade_page_num, blade_page_pos);
	using_page_num += 1;
	max_using_page_num = mymax(max_using_page_num, using_page_num);
	return blade_page_pos;
}
#endif


// 改为在 xfs_mount.h 中定义
// typedef struct {
// 	size_t pageid;
// 	size_t userpageid;
//     loff_t pos;
//     size_t count;
// } io_request;


// 初始化指定 xarray
// void init_xarray(struct xarray *xa){
// 	xa = vmalloc(sizeof(struct xarray));
// 	memset(xa, 0, sizeof(struct xarray));
// 	//xa_init(xa);
// }
//changed wtz 11.19
void init_xarray(struct xarray **xa) {
    *xa = vmalloc(sizeof(struct xarray));
    if (!*xa) {
        // printk(KERN_ERR "Failed to allocate memory for xarray\n");
        return;
    }
    xa_init(*xa);
}


// 更新指定 XArray 中的 <key, value>，如果 key 已存在，则更新值
void update_in_xarray(struct xarray *xa, long long key, long long value,ssize_t xaid) {
    unsigned long index = (unsigned long)key;
    void *entry = xa_mk_value((unsigned long)value);

    // 设置内存分配标志
    gfp_t gfp_flags = GFP_KERNEL;

    // 调用 xa_store() 进行存储，xa_store() 函数不需要显式加锁
	// printk("[UPDATE XARRAY] update key = %ld value = %d\n",index,value);
	// printk(KERN_INFO"%d\n",value);
    // xa_store(xa, index, entry, gfp_flags);

	spin_lock(&file_xarray_lock[xaid]);
	__xa_store(xa, index, entry, gfp_flags);
	spin_unlock(&file_xarray_lock[xaid]);

	// int cur_value = query_in_xarray(xa, key);
	// printk(KERN_INFO"%d\n",cur_value);
}
EXPORT_SYMBOL_GPL(update_in_xarray);


// 查找指定 XArray 中 key 对应的 value，如果不存在，返回 -1
long long query_in_xarray(struct xarray *xa, long long key,ssize_t xaid) {
    unsigned long index = (unsigned long)key;
    void *entry;

    // 查找指定 key 的条目，不需要显式加锁
    entry = xa_load(xa, index);
	// spin_lock(&file_xarray_lock[xaid]);
	// entry = __xa_load(xa, index);
	// spin_unlock(&file_xarray_lock[xaid]);

    if (entry) {
        int value = xa_to_value((unsigned long)entry);
		// printk("[QUERY XARRAY] query key = %ld value = %d\n",index,value);
        return value;
    }
	// printk("[QUERY XARRAY] query key = %ld value = -1\n",index);
    return -1;  // 如果不存在该 key，则返回 -1
}
EXPORT_SYMBOL_GPL(query_in_xarray);


// 删除指定 XArray 中的 key，如果 key 不存在，则该函数不会做任何事情
void delete_in_xarray(struct xarray *xa, long long key,ssize_t xaid) 
{
    unsigned long index = (unsigned long)key;

    // 使用 xa_erase 删除指定 key 的条目，不需要显式加锁
    xa_erase(xa, index);
	// spin_lock(&file_xarray_lock[xaid]);
	// __xa_erase(xa, index);
	// spin_unlock(&file_xarray_lock[xaid]);
}
EXPORT_SYMBOL_GPL(delete_in_xarray);


//int range_query_result[100005];

// 查找指定 XArray 中范围在 start_key 和 end_key 之间的所有 value，将所有的 value 保存在全局数组 range_query_result 中
int range_query_in_xarray_nlogn(struct xarray *xa, long long start_key, long long end_key,long long range_query_result[],ssize_t xaid) {
	// printk("-------------------------------------------------------------\n");
    unsigned long startKey = (unsigned long)start_key;
    unsigned long endKey = (unsigned long)end_key;
	// printk("startkey = %ld endkey = %ld\n",startKey,endKey);

    unsigned long index;
    void *entry;

	// 初始化 range_query_result_ed
	int range_query_result_ed = 0;

    // xa_for_each_range(xa, index, entry, startKey, endKey) {
    //     if (entry) {
    //         int value = (int)(unsigned long)entry;
	// 		range_query_result[range_query_result_ed++] = value;
    //     }
    // }
	//printk("!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    // 使用 xa_for_each_range 遍历指定范围内的所有条目,不需要显式加锁
	// xa_for_each_range(xa, index, entry, startKey, endKey) {
	// 	if (entry) {
	// 		int value = xa_to_value((unsigned long)entry);
	// 		range_query_result[range_query_result_ed++] = value;
	// 	}
	// }
	for(unsigned long i = startKey;i <= endKey;i++){
		long long value = query_in_xarray(xa,i,xaid);
		// printk("range query key = %ld value = %d\n",i,value);
		// if(value != -1){
		range_query_result[range_query_result_ed++] = value;
		// }
	}
	// printk(KERN_INFO "range_query_result_ed = %d\n",range_query_result_ed);
	// printk("-------------------------------------------------------------\n");
	return range_query_result_ed;
}
EXPORT_SYMBOL_GPL(range_query_in_xarray_nlogn);

void traverse_in_xarray(struct xarray *xa){
	// printk("-----------------TRAVERSE IN XARRAY-----------------\n");
	unsigned long index;
	void *entry;
	xa_for_each(xa, index, entry) {
		if (entry) {
			int value = (int)(unsigned long)entry;
			// printk("key = %ld value = %d\n", index, value);
		}
	}
	// printk("-----------------END TRAVERSE IN XARRAY-----------------\n");
}




size_t do_copy_from_user(char *to, char *from, size_t len){
	size_t copyret = copy_from_user(to, from, len);
	if(copyret != 0){
		printk("[DO COPY FROM USER]: copy_from_user ERROR. len = %ld copyret = %ld\n", len, copyret);
	}
	return copyret;
}

#ifdef CALCULATE_PER4K
void bio_merge_single_page_4k(int pageid, int page_in_pos, int len){
	if(allpage_4k[pageid].num == 0){
		allpage_4k[pageid].pos[0] = page_in_pos;
		allpage_4k[pageid].len[0] = len;
		allpage_4k[pageid].num += 1;
		allpage_4k[pageid].sumlen = len;
		return ;
	}

	int idxL = allpage_4k[pageid].num, idxR = -1;
    for(int i = 0;i < allpage_4k[pageid].num;i++){
        // if((allpage[pageid].pos[i] <= (page_in_pos + len - 1) && allpage[pageid].pos[i] + allpage[pageid].len[i] - 1 >= (page_in_pos + len - 1)) || ((allpage[pageid].pos[i] + allpage[pageid].len[i] - 1) >= page_in_pos && allpage[pageid].pos[i] <= page_in_pos)){
        //     if(idxL > i) idxL = i;
        //     if(idxR < i) idxR = i;
        // }
		if(allpage_4k[pageid].pos[i] <= page_in_pos + len - 1 && allpage_4k[pageid].pos[i] + allpage_4k[pageid].len[i] - 1 >= page_in_pos){
			if(idxL > i) idxL = i;
			if(idxR < i) idxR = i;
		}
    }

	// 没有重叠区间的情况：直接按顺序插入
	if(idxL == allpage_4k[pageid].num && idxR == -1){
		int firstL = -1;
		// 找到第一个大于page_in_pos的区间
		for(int i = 0;i < allpage_4k[pageid].num;i++){
			if(allpage_4k[pageid].pos[i] > page_in_pos){
				firstL = i;
				break;
			}
		}
		// 如果没有找到，则直接插入到最后
		if(firstL == -1){
			allpage_4k[pageid].pos[allpage_4k[pageid].num] = page_in_pos;
			allpage_4k[pageid].len[allpage_4k[pageid].num] = len;
			allpage_4k[pageid].num += 1;
		}
		else { // 否则插入到 firstL 位置,并将后面的区间后移
			for(int i = allpage_4k[pageid].num;i > firstL;i--){
				allpage_4k[pageid].pos[i] = allpage_4k[pageid].pos[i-1];
				allpage_4k[pageid].len[i] = allpage_4k[pageid].len[i-1];
			}
			allpage_4k[pageid].pos[firstL] = page_in_pos;
			allpage_4k[pageid].len[firstL] = len;
			allpage_4k[pageid].num += 1;
		}
		allpage_4k[pageid].sumlen += len;
	}
	else { // 有重叠区间的情况，那么重叠的区间就是 [idxL,idxR]
		// 先将当前IO请求的区间与重叠区间合并成一个新的区间
		int new_start_pos = page_in_pos;
		int new_end_pos = page_in_pos + len - 1;
		for(int i = idxL;i <= idxR;i++){
			new_start_pos = mymin(new_start_pos, allpage_4k[pageid].pos[i]);
			new_end_pos = mymax(new_end_pos, allpage_4k[pageid].pos[i] + allpage_4k[pageid].len[i] - 1);
		}
		// 将新的区间插入到 idxL 位置
		allpage_4k[pageid].pos[idxL] = new_start_pos;
		allpage_4k[pageid].len[idxL] = new_end_pos - new_start_pos + 1;
		// 将 idxR 之后的区间前移, [idxL,idxR] 之间的区间舍弃
		for(int i = idxR + 1;i < allpage_4k[pageid].num;i++){
			allpage_4k[pageid].pos[idxL + i - idxR] = allpage_4k[pageid].pos[i];
			allpage_4k[pageid].len[idxL + i - idxR] = allpage_4k[pageid].len[i];
		}
		// 更新 allpage[pageid].num
		allpage_4k[pageid].num = allpage_4k[pageid].num - (idxR - idxL);

		allpage_4k[pageid].sumlen = 0;
		for(int i = 0;i < allpage_4k[pageid].num;i++){
			allpage_4k[pageid].sumlen += allpage_4k[pageid].len[i];
		}
	}

	// 扫描所有 blade IO 段，如果有首尾相接的区间，也进行合并，为保证效率，倒序扫描
	idxR = allpage_4k[pageid].num - 1;
	while(idxR >= 0){
		idxL = idxR - 1;
		while(idxL >= 0){
			int idxL_endpos = allpage_4k[pageid].pos[idxL] + allpage_4k[pageid].len[idxL] - 1;
			int nxt_idxL_startpos = allpage_4k[pageid].pos[idxL + 1];
			if(idxL_endpos + 1 == nxt_idxL_startpos){ // 首尾相接
				idxL--;
			}
			else break;
		}

		if(idxL + 1 < idxR){ // [idxL + 1,idxR] 之间的区间首尾相接，可合并成一个新的区间
			int new_start_pos = allpage_4k[pageid].pos[idxL + 1];
			int new_end_pos = allpage_4k[pageid].pos[idxR] + allpage_4k[pageid].len[idxR] - 1;

			// 将新的区间插入到 idxL + 1 位置
			allpage_4k[pageid].pos[idxL + 1] = new_start_pos;
			allpage_4k[pageid].len[idxL + 1] = new_end_pos - new_start_pos + 1;

			allpage_4k[pageid].num -= (idxR - idxL - 1);
			// 将 idxR 之后的区间前移, [idxL + 2,idxR] 之间的区间舍弃
			for(int i = idxR + 1;i < allpage_4k[pageid].num;i++){
				allpage_4k[pageid].pos[idxL + 1 + i - idxR] = allpage_4k[pageid].pos[i];
				allpage_4k[pageid].len[idxL + 1 + i - idxR] = allpage_4k[pageid].len[i];
			}
		}
		idxR = idxL;
	}
}
#endif


BOOL is_append_write;

// 合并后判定一下是不是ready
ssize_t bio_merge_single_page(int pageid, int page_in_pos,char __user *buf, int len, size_t xaid){
	// return len;
	// printk("[BIO MERGE SINGLE PAGE]: pageid = %d page_in_pos = %d len = %d allpage[pageid].num = %d\n", pageid, page_in_pos, len, allpage[pageid].num);
// #ifdef USING_LOCK 锁上到这里(copy_from_user函数之前)会有问题，目前尚不清楚原因
// 	spin_lock(&blade_page_lock[pageid]);
// #endif

	// size_t copyret = do_copy_from_user((char*)(memorycache)+1ll*pageid*(Aligned_Size+Page_Meta_Size)+Page_Meta_Size+page_in_pos, (char*)buf , len);
	// size_t copyret = copy_from_user((char *)(allpage_data) + 1ll * pageid * Aligned_Size + page_in_pos, (char *)buf, len);
	// if(copyret != 0){
	// 	printk("[BIO MERGE SINGLE PAGE]: copy_from_user ERROR. pageid = %d page_in_pos = %d len = %d copyret = %ld\n", pageid, page_in_pos, len, copyret);
	// }

#ifdef CALCULATE_PER4K
	if(is_append_write == FALSE){
		BLADE_PAGE_OFFSET cur_offset = pageid * Aligned_Size + page_in_pos;
		while(cur_offset < pageid * Aligned_Size + page_in_pos + len){
			ssize_t cur_4k_page_id = cur_offset / Size4K;

			BOOL pre_used, pre_full;
			if(allpage_4k[cur_4k_page_id].num == 0) pre_used = FALSE;
			else pre_used = TRUE;
			if(pre_used == TRUE && allpage_4k[cur_4k_page_id].sumlen == Size4K) pre_full = TRUE;
			else pre_full = FALSE;

			BLADE_PAGE_OFFSET update_pos = cur_offset % Size4K;
			BLADE_PAGE_OFFSET update_len = mymin(Size4K - update_pos, pageid * Aligned_Size + page_in_pos + len - cur_offset);

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
	}
#endif


#ifdef USING_LOCK
	spin_lock(&blade_page_lock[pageid]);
#endif

	// if(len >= 16*1024 || len < 0)
	// 	printk("!!!!!!!!  len = %d\n",len);
    if(allpage_meta[pageid].num == 0){
        allpage_meta[pageid].pos[0] = page_in_pos;
        allpage_meta[pageid].len[0] = len;
		allpage_meta[pageid].num += 1;
		// printk("!!!!!i am ready to go out!!!!!!!!!!\n");
        // return 1; 

#ifdef DOFLUSH
		if(len == Aligned_Size){ // 当前页已满
#ifndef ONLY_READSSD
			// spin_lock(&flush_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
			spin_lock(&flush_queue_lock[0]);
			CircularQueue_push(flush_circular_queue[0], pageid, xaid);
			// atomic_inc(&ready_blade_page_num[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
			atomic_inc(&ready_blade_page_num[0]);
			// printk("[MERGE PAGE]: pageid = %d is full.\n", pageid);
			// CircularQueue_push(flush_circular_queue[allpage[pageid].FLBid % FLUSH_THREAD_NUM], pageid);
			// spin_unlock(&flush_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
			spin_unlock(&flush_queue_lock[0]);
#endif
		}
		else { // 当前页未满，暂时的策略是直接将该页插入到 readssd_circular_queue 中, 由后台线程负责从 SSD 读取数据
#ifndef ONLY_FLUSH
			// spin_lock(&readssd_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
			spin_lock(&readssd_queue_lock[0]);
			CircularQueue_push(readssd_circular_queue[0], pageid, xaid);
			atomic_inc(&unready_blade_page_num[0]);
			// printk("[BIO MERGE]: readssd queue length = %ld  unready_blade_page_num = %ld", CircularQueue_length(readssd_circular_queue[0]), atomic_read(&unready_blade_page_num[0]));
			// printk("[MERGE PAGE]: pageid = %d is not full.\n", pageid);
			// CircularQueue_push(readssd_circular_queue[allpage[pageid].FLBid % FLUSH_THREAD_NUM], pageid);
			// spin_unlock(&readssd_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
			spin_unlock(&readssd_queue_lock[0]);
#endif
		}
		// printk("[BIO MERGE SINGLE PAGE]: ready queue length = %ld unready queue length = %ld", CircularQueue_length(flush_circular_queue[pageid % FLUSH_THREAD_NUM]), CircularQueue_length(readssd_circular_queue[pageid % FLUSH_THREAD_NUM]));
#endif

		// printk("[MERGE_PAGE_EXIT]: pageid = %d num == 0\n", pageid);
#ifdef USING_LOCK
		spin_unlock(&blade_page_lock[pageid]);
		// spin_unlock(&flush_queue_lock[0]);
#endif
		max_blade_page_io_num = mymax(max_blade_page_io_num, allpage_meta[pageid].num);

		return len;
    }
	//do_io directly
	
	//copy_from_user((char*)dio_buf, (char*)(from->ubuf) + L_Size, buf_size - L_Size - R_Size);	

	// [idxL,idxR] 描述了当前page中与当前IO请求有重叠的区间

	if(allpage_meta[pageid].num >= 127){
		printk("[BIO MERGE SINGLE PAGE]: ERROR NUM. num >= 127. num = %d", allpage_meta[pageid].num);
#ifdef USING_LOCK
		spin_unlock(&blade_page_lock[pageid]);
#endif
		return len;
	}

	// for(int i = 0;i < allpage[pageid].num;i++){
	// 	if(allpage[pageid].pos[i] < 0 || allpage[pageid].pos[i] > Aligned_Size || allpage[pageid].len[i] < 0 || allpage[pageid].len[i] > Aligned_Size){
	// 		printk("[BIO MERGE SINGLE PAGE]: ERROR POS. num = %d pageid = %d pos[%d] = %d len = %d new_pos = %d new_len = %d\n", allpage[pageid].num, pageid, i, allpage[pageid].pos[i], allpage[pageid].len[i], page_in_pos, len);
	// 	}
	// }

	// if(allpage[pageid].num < 0){
	// 	printk("[BIO MERGE SINGLE PAGE]: ERROR NUM. num < 0. pageid = %d num = %ld", pageid, allpage[pageid].num);
	// }

	


    int idxL = allpage_meta[pageid].num, idxR = -1;
    for(int i = 0;i < allpage_meta[pageid].num;i++){
        // if((allpage[pageid].pos[i] <= (page_in_pos + len - 1) && allpage[pageid].pos[i] + allpage[pageid].len[i] - 1 >= (page_in_pos + len - 1)) || ((allpage[pageid].pos[i] + allpage[pageid].len[i] - 1) >= page_in_pos && allpage[pageid].pos[i] <= page_in_pos)){
        //     if(idxL > i) idxL = i;
        //     if(idxR < i) idxR = i;
        // }
		if(allpage_meta[pageid].pos[i] <= page_in_pos + len - 1 && allpage_meta[pageid].pos[i] + allpage_meta[pageid].len[i] - 1 >= page_in_pos){
			if(idxL > i) idxL = i;
			if(idxR < i) idxR = i;
		}
    }

	// 没有重叠区间的情况：直接按顺序插入
	if(idxL == allpage_meta[pageid].num && idxR == -1){
		int firstL = -1;
		// 找到第一个大于page_in_pos的区间
		for(int i = 0;i < allpage_meta[pageid].num;i++){
			if(allpage_meta[pageid].pos[i] > page_in_pos){
				firstL = i;
				break;
			}
		}
		// 如果没有找到，则直接插入到最后
		if(firstL == -1){
			allpage_meta[pageid].pos[allpage_meta[pageid].num] = page_in_pos;
			allpage_meta[pageid].len[allpage_meta[pageid].num] = len;
			allpage_meta[pageid].num += 1;
		}
		else { // 否则插入到 firstL 位置,并将后面的区间后移
			for(int i = allpage_meta[pageid].num;i > firstL;i--){
				allpage_meta[pageid].pos[i] = allpage_meta[pageid].pos[i-1];
				allpage_meta[pageid].len[i] = allpage_meta[pageid].len[i-1];
			}
			allpage_meta[pageid].pos[firstL] = page_in_pos;
			allpage_meta[pageid].len[firstL] = len;
			allpage_meta[pageid].num += 1;
		}
	}
	else { // 有重叠区间的情况，那么重叠的区间就是 [idxL,idxR]
		// 先将当前IO请求的区间与重叠区间合并成一个新的区间
		int new_start_pos = page_in_pos;
		int new_end_pos = page_in_pos + len - 1;
		for(int i = idxL;i <= idxR;i++){
			new_start_pos = mymin(new_start_pos, allpage_meta[pageid].pos[i]);
			new_end_pos = mymax(new_end_pos, allpage_meta[pageid].pos[i] + allpage_meta[pageid].len[i] - 1);
		}
		// 将新的区间插入到 idxL 位置
		allpage_meta[pageid].pos[idxL] = new_start_pos;
		allpage_meta[pageid].len[idxL] = new_end_pos - new_start_pos + 1;
		// 将 idxR 之后的区间前移, [idxL,idxR] 之间的区间舍弃
		for(int i = idxR + 1;i < allpage_meta[pageid].num;i++){
			allpage_meta[pageid].pos[idxL + i - idxR] = allpage_meta[pageid].pos[i];
			allpage_meta[pageid].len[idxL + i - idxR] = allpage_meta[pageid].len[i];
		}
		// 更新 allpage[pageid].num
		allpage_meta[pageid].num = allpage_meta[pageid].num - (idxR - idxL);
	}

	// 扫描所有 blade IO 段，如果有首尾相接的区间，也进行合并，为保证效率，倒序扫描
	idxR = allpage_meta[pageid].num - 1;
	while(idxR >= 0){
		idxL = idxR - 1;
		while(idxL >= 0){
			int idxL_endpos = allpage_meta[pageid].pos[idxL] + allpage_meta[pageid].len[idxL] - 1;
			int nxt_idxL_startpos = allpage_meta[pageid].pos[idxL + 1];
			if(idxL_endpos + 1 == nxt_idxL_startpos){ // 首尾相接
				idxL--;
			}
			else break;
		}

		if(idxL + 1 < idxR){ // [idxL + 1,idxR] 之间的区间首尾相接，可合并成一个新的区间
			int new_start_pos = allpage_meta[pageid].pos[idxL + 1];
			int new_end_pos = allpage_meta[pageid].pos[idxR] + allpage_meta[pageid].len[idxR] - 1;

			// 将新的区间插入到 idxL + 1 位置
			allpage_meta[pageid].pos[idxL + 1] = new_start_pos;
			allpage_meta[pageid].len[idxL + 1] = new_end_pos - new_start_pos + 1;

			allpage_meta[pageid].num -= (idxR - idxL - 1);
			// 将 idxR 之后的区间前移, [idxL + 2,idxR] 之间的区间舍弃
			for(int i = idxR + 1;i < allpage_meta[pageid].num;i++){
				allpage_meta[pageid].pos[idxL + 1 + i - idxR] = allpage_meta[pageid].pos[i];
				allpage_meta[pageid].len[idxL + 1 + i - idxR] = allpage_meta[pageid].len[i];
			}
		}
		idxR = idxL;
	}




#ifdef DOFLUSH
	// 检查当前页是否已满
	int sumLen = 0;
	for(int i = 0;i < allpage_meta[pageid].num;i++){
		sumLen += allpage_meta[pageid].len[i];
	}

	if(sumLen == Aligned_Size){ // 当前页已满
#ifndef ONLY_READSSD
		// spin_lock(&flush_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
		spin_lock(&flush_queue_lock[0]);
		// atomic_inc(&ready_blade_page_num[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
		CircularQueue_push(flush_circular_queue[0], pageid, xaid);
		atomic_inc(&ready_blade_page_num[0]);
		// printk("[MERGE PAGE]: pageid = %d is full.\n", pageid);
		// CircularQueue_push(flush_circular_queue[allpage[pageid].FLBid % FLUSH_THREAD_NUM], pageid);
		// CircularQueue_print(flush_circular_queue[pageid % FLUSH_THREAD_NUM]);
		// spin_unlock(&flush_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
		spin_unlock(&flush_queue_lock[0]);
#endif
	}
	else { // 当前页未满，暂时的策略是直接将该页插入到 readssd_circular_queue 中, 由后台线程负责从 SSD 读取数据
#ifndef ONLY_FLUSH
		// spin_lock(&readssd_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
		spin_lock(&readssd_queue_lock[0]);
		CircularQueue_push(readssd_circular_queue[0], pageid, xaid);
		atomic_inc(&unready_blade_page_num[0]);
		// printk("[BIO MERGE]: readssd queue length = %ld  unready_blade_page_num = %ld", CircularQueue_length(readssd_circular_queue[0]), atomic_read(&unready_blade_page_num[0]));
		// printk("[MERGE PAGE]: pageid = %d is not full.\n", pageid);
		// CircularQueue_push(readssd_circular_queue[allpage[pageid].FLBid % FLUSH_THREAD_NUM], pageid);
		// spin_unlock(&readssd_queue_lock[allpage[pageid].FLBid % FLUSH_THREAD_NUM]);
		spin_unlock(&readssd_queue_lock[0]);
#endif
	}
	// printk("[BIO MERGE SINGLE PAGE]: ready queue length = %ld unready queue length = %ld", CircularQueue_length(flush_circular_queue[pageid % FLUSH_THREAD_NUM]), CircularQueue_length(readssd_circular_queue[pageid % FLUSH_THREAD_NUM]));
#endif


	// 审查维护好的区间是否递增并且是否有重叠，如果有则报错
	// for(int i = 0;i < allpage[pageid].num - 1;i++){
	// 	if(allpage[pageid].pos[i] + allpage[pageid].len[i] - 1 >= allpage[pageid].pos[i + 1]){
	// 		printk("Error: Overlap in page %d\n", pageid);
	// 		printk("pos[%d] = %d, len[%d] = %d\n", i, allpage[pageid].pos[i], i, allpage[pageid].len[i]);
	// 		printk("pos[%d] = %d, len[%d] = %d\n", i + 1, allpage[pageid].pos[i + 1], i + 1, allpage[pageid].len[i + 1]);
	// 	}
	// 	if(allpage[pageid].pos[i] > allpage[pageid].pos[i + 1]){
	// 		printk("Error: Not in increasing order in page %d\n", pageid);
	// 		printk("pos[%d] = %d, len[%d] = %d\n", i, allpage[pageid].pos[i], i, allpage[pageid].len[i]);
	// 		printk("pos[%d] = %d, len[%d] = %d\n", i + 1, allpage[pageid].pos[i + 1], i + 1, allpage[pageid].len[i + 1]);
	// 	}
	// }


	max_blade_page_io_num = mymax(max_blade_page_io_num, allpage_meta[pageid].num);
#ifdef USING_LOCK	
	spin_unlock(&blade_page_lock[pageid]);
	// spin_unlock(&flush_queue_lock[0]);
#endif
	return len;
	
}
EXPORT_SYMBOL_GPL(bio_merge_single_page);

void traverse_allpage_bladeIO(size_t pageid){
	printk("-----------------TRAVERSE ALLPAGE BLADEIO-----------------");
	printk("pageid = %d num = %ld",pageid, allpage_meta[pageid].num);
	for(int i = 0;i < allpage_meta[pageid].num;i++){
		printk("pos[%d] = %d len[%d] = %d", i, allpage_meta[pageid].pos[i], i, allpage_meta[pageid].len[i]);
	}
	printk("-----------------END TRAVERSE ALLPAGE BLADEIO-----------------");
}


void useless_alloc(void){

#ifdef OPEN_USELESS_ALLOC
	void *tempbuf = vmalloc(Aligned_Size);
	vfree(tempbuf);
#endif

}

void useless_for(void){
	for(int i = 0;i < 10000;i++){
		int a = 1;
	}
}

int dio_page_num = 3;
int using_page_num_threshold = 4096;
void mydelay(void){
	// i == 70 for webproxy 16thread 221 15s 5GB 17129pages
	// usleep_range(100, 110);
}


inline size_t xxfs_bio_write(size_t pos, char __user *buf, size_t len, size_t flag, size_t xaid)
{	
	// printk("[XXFS BIO WRITE]: pos = %ld len = %ld flag = %ld xaid = %ld\n", pos, len, flag, xaid);
	// return 0;
	size_t ret = 0;
	// 记得上范围锁
	
	if(flag == 3)
	{
		// printk("come in-biowrite-flag=3\n");
		int nowpage1 = query_in_xarray(myxa[xaid], pos/Aligned_Size,xaid);
		int nowpage2 = query_in_xarray(myxa[xaid], (pos + len - 1)/Aligned_Size,xaid);
		// printk("pre nowpage1 = %d nowpage2 = %d\n",nowpage1,nowpage2);
		if(nowpage1<0)
		{
#ifdef BOTH_ENDS_ALLOC
			ALLOC_TYPE alloc_type;
			while(1){
				if(spin_trylock(&top_alloc_lock)){
					alloc_type = TYPE_TOP;
					break;
				}
				if(spin_trylock(&bottom_alloc_lock)){
					alloc_type = TYPE_BOTTOM;
					break;
				}
			}
			nowpage1 = alloc_blade_page(alloc_type);
			update_in_xarray(myxa[xaid], pos/Aligned_Size,nowpage1);
			if(alloc_type == TYPE_TOP){
				spin_unlock(&top_alloc_lock);
			}
			else{
				spin_unlock(&bottom_alloc_lock);
			}
			useless_alloc();
			allpage[nowpage1].FLBid = pos / Chunk_Size;
#else
			if(using_page_num >= using_page_num_threshold){
				mydelay();
			}
#ifdef USING_LOCK // 测试证明，alloc_blade_page 和 update_in_xarray 必须视为一个原子操作
			spin_lock(&bitmap_lock[0]);
#endif
			nowpage1 = alloc_blade_page();
#ifdef USING_LOCK
			spin_unlock(&bitmap_lock[0]);
#endif
			update_in_xarray(myxa[xaid], pos/Aligned_Size, nowpage1, xaid);
			// update_in_xarray(myxa[xaid], pos/Aligned_Size,nowpage1,xaid);
			useless_alloc();
			// spin_lock(&blade_page_lock[nowpage1]);
			allpage_meta[nowpage1].user_pageid = pos / Aligned_Size;
			// if(pos % Chunk_Size != 0){
			// 	printk("[CHUNK SIZE]: pos mod not 0\n");
			// }
			// spin_unlock(&blade_page_lock[nowpage1]);
#endif
		}
		if(nowpage2<0){
#ifdef BOTH_ENDS_ALLOC
			ALLOC_TYPE alloc_type;
			while(1){
				if(spin_trylock(&top_alloc_lock)){
					alloc_type = TYPE_TOP;
					break;
				}
				if(spin_trylock(&bottom_alloc_lock)){
					alloc_type = TYPE_BOTTOM;
					break;
				}
			}
			nowpage2 = alloc_blade_page(alloc_type);
			update_in_xarray(myxa[xaid], (pos + len - 1)/Aligned_Size,nowpage2);
			if(alloc_type == TYPE_TOP){
				spin_unlock(&top_alloc_lock);
			}
			else{
				spin_unlock(&bottom_alloc_lock);
			}
			useless_alloc();
			allpage[nowpage2].FLBid = (pos + len - 1) / Chunk_Size;
#else
			if(using_page_num >= using_page_num_threshold){
				mydelay();
			}
#ifdef USING_LOCK
			spin_lock(&bitmap_lock[0]);
#endif
			nowpage2 = alloc_blade_page();
#ifdef USING_LOCK
			spin_unlock(&bitmap_lock[0]);
#endif
			update_in_xarray(myxa[xaid], (pos + len - 1)/Aligned_Size, nowpage2, xaid);
			useless_alloc();
			// spin_lock(&blade_page_lock[nowpage2]);
			allpage_meta[nowpage2].user_pageid = (pos + len - 1) / Aligned_Size;
			// if((pos + len - 1) % Chunk_Size != 0){
			// 	printk("[CHUNK SIZE]: pos + len - 1 mod not 0\n");
			// }
			// spin_unlock(&blade_page_lock[nowpage2]);
#endif
		}
		// printk("aft nowpage1 = %d nowpage2 = %d\n",nowpage1,nowpage2);
		size_t L_Size = Aligned_Size - pos%Aligned_Size;
		// printk("ready to come in-biomerge_single_page-flag=3\n");
		// spin_lock(&blade_page_lock[nowpage1]);
		ret = bio_merge_single_page(nowpage1, pos%Aligned_Size, buf, L_Size, xaid);
		// spin_unlock(&blade_page_lock[nowpage1]);

		// spin_lock(&blade_page_lock[nowpage1]);
		ret += bio_merge_single_page(nowpage2, 0, buf + L_Size, len-L_Size, xaid);
		// spin_unlock(&blade_page_lock[nowpage1]);
	}
	else
	{
		int nowpage=query_in_xarray(myxa[xaid],pos/Aligned_Size,xaid);
		if(nowpage<0){
#ifdef BOTH_ENDS_ALLOC
			ALLOC_TYPE alloc_type;
			while(1){
				if(spin_trylock(&top_alloc_lock)){
					alloc_type = TYPE_TOP;
					break;
				}
				if(spin_trylock(&bottom_alloc_lock)){
					alloc_type = TYPE_BOTTOM;
					break;
				}
			}
			nowpage = alloc_blade_page(alloc_type);
			update_in_xarray(myxa[xaid], pos/Aligned_Size,nowpage);
			if(alloc_type == TYPE_TOP){
				spin_unlock(&top_alloc_lock);
			}
			else{
				spin_unlock(&bottom_alloc_lock);
			}
			useless_alloc();
			allpage[nowpage].FLBid = pos / Chunk_Size;
#else
			if(using_page_num >= using_page_num_threshold){
				mydelay();
			}
#ifdef USING_LOCK
			spin_lock(&bitmap_lock[0]);
#endif
			nowpage = alloc_blade_page();
#ifdef USING_LOCK
			spin_unlock(&bitmap_lock[0]);
#endif
			update_in_xarray(myxa[xaid], pos/Aligned_Size, nowpage, xaid);
			useless_alloc();
			// spin_lock(&blade_page_lock[nowpage]);
			allpage_meta[nowpage].user_pageid = pos / Aligned_Size;
			// if(pos % Chunk_Size != 0){
			// 	printk("[CHUNK SIZE]: pos mod not 0\n");
			// }
			// spin_unlock(&blade_page_lock[nowpage]);
#endif
		}
		// spin_lock(&blade_page_lock[nowpage]);
		ret = bio_merge_single_page(nowpage, pos%Aligned_Size, buf, len, xaid);
		// spin_unlock(&blade_page_lock[nowpage]);
	}

	// 做完解锁
	// 此时xxfs并没有分配数据块
	// printk("[XXFS_BIO_WRITE]: max_blade_page_io_num = %d\n", max_blade_page_io_num);

	return ret;
}




// 查找指定 XArray 中范围在 start_key 和 end_key 之间的所有 value，将所有的 value 保存在全局数组 range_query_result 中
// xas 版本
// void range_query_in_xarray_n_nolock(struct xarray *xa, int start_key, int end_key){
// 	unsigned long startKey = (unsigned long)start_key;
//     unsigned long endKey = (unsigned long)end_key;
// 	void *entry;

// 	// 初始化 range_query_result_ed
// 	range_query_result_ed = 0;

// 	// 声明并初始化一个 xa_state 结构体
// 	XA_STATE(xas, xa, startKey);

// 	for(entry = xas_find(xas, endKey); entry ; entry = xas_next_entry(xas, endKey)){
// 		int value = (int)(unsigned long)entry;	
// 		range_query_result[range_query_result_ed++] = value;
// 		allpage[value].lock = 1;
// 	}
// }

//XARRAY本身实现了索引结构上的锁
//然而文件锁，尤其是blade page锁尚未考虑
//后续可能需要综合考虑索引锁和blade page锁，尽可能减少锁开销
// void *dio_buf = NULL;
// EXPORT_SYMBOL(dio_buf);
s64 sum;
s64 sum_dio_write;

//测试ioviter状态
void print_iov_iter(struct iov_iter *iter) {
    // printk(KERN_INFO "iov_iter state:\n");
    // printk(KERN_INFO "  type: %d\n", iov_iter_type(iter));
    // printk(KERN_INFO "  data_source: %u\n", iter->data_source);
    // printk(KERN_INFO "  count: %zu\n", iov_iter_count(iter));
    // printk(KERN_INFO "  nr_segs: %u\n", iter->nr_segs);
    // printk(KERN_INFO "  iov_offset: %zu\n", iter->iov_offset);    
}
#endif



#ifdef XXFS
STATIC ssize_t
xfs_file_write_iter(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	// ktime_t start_all,end_all;
	// ktime_t start_copy,end_copy;
	// ktime_t start_diobuf,end_diobuf;
	// ktime_t start_ioviter,end_ioviter;
	// ktime_t start_diowrite,end_diowrite;
	// start_all = ktime_get();
	// iocb 一次文件IO操作 包含文件指针、偏移量等
	struct inode		*inode = iocb->ki_filp->f_mapping->host; // 获取文件inode
	// ki_flip 指向文件描述符的指针，代表一个打开的文件(struct file)。每个打开的文件都与一个file结构相关联
	// f_mapping 是struct file中的一个成员,指向address_space 代表文件内容在内存中的映射，用于管理文在页缓存中的映射。
	// host 是struct address_space中的一个成员，指向struct inode. 存储了文件或目录的元数据。
	
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;
	ssize_t RET = from->count;

	if(from->count >= 4ll * 1024 * 1024) is_append_write = TRUE;
	else {
		is_append_write = FALSE;
		write_iter_opt += 1;
	}


#ifdef CALCULATE_PER4K
	// used_page_4k_num_array[write_iter_opt] = used_page_4k_num;
	// full_page_4k_num_array[write_iter_opt] = full_page_4k_num;
#endif

#ifdef CALCULATE_STORAGE_PERCENT
	// sum_storage_bytes_array[write_iter_opt] = sum_storage_bytes;
	// sum_storage_bytes_include_delete_array[write_iter_opt] = sum_storage_bytes_include_delete;
	// sum_write_bytes_array[write_iter_opt] = sum_write_bytes;
#endif

	// udelay(5000);


	// printk("[WRITE ITER]: iocb->ki_pos = %ld len = %ld inode = %ld", iocb->ki_pos, from->count, XFS_I(inode)->i_ino);

	// printk("[WRITE ITER]: pos = %ld from->count = %ld", iocb->ki_pos, from->count);

	// printk(KERN_INFO " Before iocb->ki_pos = %ld:\n",iocb->ki_pos);
#ifdef DOFLUSH
	if(from->count == 9ll * 1024 * 1024 + 4096){
#ifndef ONLY_READSSD
		set_now_time(&now_time);

		// 距离上次实际 IO 时间超过 1s，且距离挂载时间超过 1s，打印内核状态
		if(get_time_diff_nsec(&last_real_io_time, &now_time) > TIME_MSEC_TO_NSEC(1000) && get_time_diff_nsec(&mount_time, &now_time) > TIME_MSEC_TO_NSEC(8000)){
			if(print_kernel_state_opt <= 30){
				print_kernel_state();
			}
		}

		int wait_num = 0;
		// printk("[DO FLUSHING]: enter deep copy.");
		// deep copy
		deep_copy_kiocb(iocb,&(flush_io_info->iocb));
		// deep_copy_iov_iter(from,&(flush_io_info->iter),TRUE);
		flush_io_info->iocb->ki_flags |= IOCB_DIRECT;
		// flush_io_info->iter->data_source = WRITE; // 设置为写操作

		// printk("[DO FLUSHING]: successfully deep copy. prepare to flush.");

		atomic64_set(&flush_write_blocked, 1);

		while(atomic64_read(&flush_write_blocked) == 1 && wait_num < 100000){
			wait_num++;
			// printk("[DO FLUSHING]: waiting for flush. waiting 50us. wait_num = %d", wait_num);
			// udelay(50);
			usleep_range(10,15);
		}

		// vfree(flush_io_info->iocb);
		// flush_io_info->iocb = NULL;
		// vfree(flush_io_info->iter);
		// flush_io_info->iter = NULL;
		// vfree(flush_io_info);
		// flush_io_info = NULL;
#endif
		return RET;
	}
#endif



	set_now_time(&last_real_io_time);


	// if(flush_io_info->iocb == NULL && flush_io_info->iter == NULL){
	// 	// printk("[FLUSH IO INFO]: enter flush io info!");
	// 	// show_time();
	// 	// 深拷贝 iocb
	// 	// 深拷贝 iov_iter 
	// 	// flush_io_info->iocb = (struct kiocb *)kmalloc(sizeof(struct kiocb), GFP_KERNEL);
	// 	// flush_io_info->iter = (struct iov_iter *)kmalloc(sizeof(struct iov_iter), GFP_KERNEL);
	// 	deep_copy_kiocb(iocb,&(flush_io_info->iocb));
	// 	deep_copy_iov_iter(from,&(flush_io_info->iter),TRUE);
	// 	// memcpy(flush_io_info->iocb, iocb, sizeof(struct kiocb));
	// 	// memcpy(flush_io_info->iter, from, sizeof(struct iov_iter));
	// 	flush_io_info->iocb->ki_flags |= IOCB_DIRECT;
	// 	flush_io_info->iter->data_source = WRITE; // 设置为写操作
	// 	// flush_io_info->iter = (struct iov_iter *)kmalloc(sizeof(struct iov_iter), GFP_KERNEL);
	// 	// memcpy(flush_io_info->iter, from, sizeof(struct iov_iter));

	// 	// flush_io_info->iocb->ki_pos = 0;
	// 	// size_t len = Aligned_Size;
	// 	// void *dio_buf = vmalloc(len);
	// 	// // 将 allpage[blade_page_id] 中的数据拷贝到 dio_buf 中
	// 	// // memcpy(dio_buf, (char *)(memorycache) + pos + Page_Meta_Size, len);
	// 	// // 为 dio_buf 随机写入一些数据，测试下刷效果
	// 	// for(int i = 0;i < len;i++){
	// 	// 	*((char *)dio_buf + i) = ('a') + (i % 26);
	// 	// }

	// 	// // 定义 kvec，指向 dio_buf
	// 	// struct kvec kvec;
	// 	// kvec.iov_base = dio_buf;
	// 	// kvec.iov_len = len;
	// 	// // 定义 iov_iter
	// 	// struct iov_iter new_iter;
	// 	// // iov_iter_kvec(&new_iter, flush_io_info->iter->data_source, &kvec, flush_io_info->iter->nr_segs, kvec.iov_len);
	// 	// iov_iter_kvec(&new_iter, from->data_source, &kvec, from->nr_segs, kvec.iov_len);


	// 	// ssize_t ret = xfs_file_dio_write(iocb, &new_iter);
	// 	// if(ret <= 0){
	// 	// 	printk("[DO FLUSHING]: do_flushing failed! return ret = %lld", ret);
	// 	// }
	// 	// else{
	// 	// 	printk("[DO FLUSHING]: do_flushing successfully! flush %lld bytes", ret);
	// 	// }
	// 	// vfree(dio_buf);
	// }
	// if(readssd_io_info->iocb == NULL && readssd_io_info->iter == NULL){
	// 	// printk("[READ SSD IO INFO]: enter read ssd io info!");
	// 	show_time();
	// 	// 深拷贝 iocb
	// 	// 深拷贝 iov_iter
		
	// 	deep_copy_kiocb(iocb,&(readssd_io_info->iocb));
	// 	deep_copy_iov_iter(from,&(readssd_io_info->iter),TRUE);


	// 	readssd_io_info->iocb->ki_flags = 0; // 经测试，读操作的 ki_flags 为 0
	// 	readssd_io_info->iter->data_source = READ; // 设置为读操作

	// 	// ssize_t ret = xfs_file_buffered_read(readssd_io_info->iocb,readssd_io_info->iter);
	// 	// if(ret <= 0){
	// 	// 	printk("[READ FROM SSD]: read_from_SSD failed! return ret = %lld.\n", ret);
	// 	// }
	// 	// else{
	// 	// 	printk("[READ FROM SSD]: read_from_SSD successfully! read %lld bytes.\n", ret);
	// 	// }

	// }
	
	// printk("[FLUSH IO INFO]: iocb->ki_pos = %ld flush->ki_pos = %ld from->count = %ld flush->count = %ld\n", iocb->ki_pos,flush_io_info->iocb->ki_pos,from->count,flush_io_info->iter->count);

	

	//ip->i_ino 唯一标识id 但是id可能非常大，目前先强行假设它最大1000w
	// printk("ip->i_ino = %lld\n",ip->i_ino);
	
	// 插入文件 inode 号记录
	// update_in_xarray(file_inode_xa, ip->i_ino, 1);
	// if(iocb->ki_pos % Aligned_Size != 0 || from->count % Aligned_Size != 0){
	// 	printk("[WRITE ITER]: write not aligned.");
	// 	printk("iocb->ki_pos = %ld, from->count = %ld\n", iocb->ki_pos, from->count);
	// 	printk("iocb->ki_page_in_pos = %ld", iocb->ki_pos % Aligned_Size);
	// }

	size_t inode_id_temp = get_hashcode(ip->i_ino);

	// 检测哈希碰撞
	if(xarray_hash_code_table[inode_id_temp] == -1){ // 未记录
		xarray_hash_code_table[inode_id_temp] = ip->i_ino;
	}
	else if(xarray_hash_code_table[inode_id_temp] != ip->i_ino){ // 已经记录过，并且不相等，说明发生了哈希碰撞
		printk("[WRITE ITER XARRAY HASH COLLISION]: collision_code = %ld. recorded_num = %ld, new_num = %ld\n", inode_id_temp, xarray_hash_code_table[inode_id_temp], ip->i_ino);
	}

	if (inode_id_temp >= 10000000 || !myxa || !myxa_val) {
		// printk(KERN_ERR "Invalid inode or uninitialized structures\n");
    	return -EINVAL;
	}
	// printk("ip->i_ino = %lld\n",ip->i_ino);
	// if(myxa_val[ip->i_ino]==0)
	// {
	// 	init_xarray(myxa[ip->i_ino]);
	// 	myxa_val[ip->i_ino]=1;
	// }
	//changed wtz 11.19

	// int blg_idx = -1;

	// spin_lock(&blg_lock);

	// for(int i = 0;i < blg_ed;i++){
	// 	if(blg[i] == ip->i_ino){
	// 		blg_idx = i;
	// 		break;
	// 	}
	// }

	// if(blg_idx == -1){
	// 	blg_idx = blg_ed;
	// 	blg[ blg_ed++ ] = ip->i_ino;
	// }

	// inode_id_temp = blg_idx;

	// spin_unlock(&blg_lock);



	if (myxa_val[inode_id_temp] == 0) {
		// printk("[WIRTE ITER]: init xarray not int mount. inode_id_temp = %ld\n", inode_id_temp);
    	init_xarray(&myxa[inode_id_temp]);  // 初始化 xarray
    	if (!myxa[inode_id_temp]) {
			// printk(KERN_ERR "Failed to initialize xarray for inode %llu\n", ip->i_ino);
        	return -ENOMEM;
    	}
    	myxa_val[inode_id_temp] = 1;
	}

	
	size_t	ocount = iov_iter_count(from);

	XFS_STATS_INC(ip->i_mount, xs_write_calls);

	if (ocount == 0)
		return 0;

	if (xfs_is_shutdown(ip->i_mount))
		return -EIO;

	if (IS_DAX(inode))
		return xfs_file_dax_write(iocb, from);


	if (iocb->ki_flags & IOCB_DIRECT) {
		/*
		 * Allow a directio write to fall back to a buffered
		 * write *only* in the case that we're doing a reflink
		 * CoW.  In all other directio scenarios we do not
		 * allow an operation to fall back to buffered mode.
		 */
		ret = xfs_file_dio_write(iocb, from);
		if (ret != -ENOTBLK)
			return ret;
	}
#ifdef XXFS
	//modify
	// int from_count1 = from->count;
	// printk("*******************************\n");
	// printk("!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	// printk("ocount = %ld\n",ocount);
	iocb->ki_flags |= IOCB_DIRECT;
	size_t user_pos = (size_t)iocb->ki_pos;
	// printk("user_pos = %ld\n",user_pos);
	// printk("from->count = %ld",from->count);
	// printk("ocount(iov_iter_count) = %ld",ocount);
	size_t L_Size, R_Size;
	if((user_pos/Aligned_Size) == ((user_pos + from->count - 1)/Aligned_Size)) //请求在一个blade page中
	{	
		// printk("trace flag-1*************start!!!");
		size_t result1 = user_pos/Aligned_Size;
		// TODO: 这里的计算有问题，应该是 (user_pos + from->count - 1)/Aligned_Size
		size_t result2 = (user_pos + from->count - 1)/Aligned_Size;
		// printk("user_pos/alignsized = %ld, (user_pos + from->count)/alignedsize = %ld\n",result1,result2);
		L_Size = from->count;
		R_Size = 0;
		// printk(" L_Size = %ld , R_Size = %ld\n",L_Size,R_Size);
	}
	else
	{
		L_Size = Aligned_Size - user_pos%Aligned_Size;
		if(L_Size == Aligned_Size)
			L_Size = 0;
		R_Size = (user_pos + from->count)%Aligned_Size;
		// printk("L_Size = %ld, R_Size = %ld, user_pos Aligned_Size = %ld\n",L_Size,R_Size,user_pos%Aligned_Size);
	}
	if(( (user_pos/Aligned_Size) == ((user_pos + from->count - 1)/Aligned_Size) ) && from->count == Aligned_Size){
		L_Size = R_Size = 0;
	}

	// printk("from->count = %ld",from->count);
	BOOL D_flag = TRUE;

	size_t flag;
	ASSERT(L_Size >= 0);
	ASSERT(R_Size >= 0);
	// printk("[INFO]: L_Size = %d R_Size = %d\n",L_Size,R_Size);
	// printk("[WRITE INFO]: start_page = %d start_pos = %d end_page = %d end_pos = %d L_Size = %d R_Size = %d\n", iocb->ki_pos / Aligned_Size, iocb->ki_pos % Aligned_Size ,(iocb->ki_pos + from->count - 1) / Aligned_Size, (iocb->ki_pos + from->count - 1) % Aligned_Size, L_Size, R_Size);
	if(L_Size == 0 && R_Size == 0){
		flag = 0;
		ret = 0;
		// printk("[INFO]: come in-flag-0\n");
		// printk("********************************************\n");
		// printk("pass-flag-0\n");
		// printk("********************************************\n");
#ifdef FLEXIBLE_DIO_WRITE // 采用灵活的 DIO 写入策略：中间页原本会走 directIO，现在判定如果页数小于等于 2，则中间页直接走 bladeIO
		const size_t MID_PAGE_NUM_THRESHOLD = dio_page_num; // 中间页会直接走 bladeIO 的阈值

		const size_t mid_page_num = (from->count - L_Size - R_Size) / Aligned_Size;
		if(mid_page_num <= MID_PAGE_NUM_THRESHOLD){ // 小于阈值，中间满页走 blade IO
			for(int i = 0;i < mid_page_num;i++){
				size_t offset = L_Size + i * Aligned_Size;
				ssize_t ret = xxfs_bio_write(iocb->ki_pos + offset, from->ubuf + offset, Aligned_Size, 5, inode_id_temp);
			}
			D_flag = FALSE;
		}
		// 大于阈值，无事发生，继续执行原先的逻辑
#endif
	}
	else if(R_Size == 0){
		flag = 1;
		// printk("********************************************");
		// printk("come in-flag-1");
		// printk("********************************************");
		// printk("[INFO]: come in-flag-1\n");
		ret = xxfs_bio_write(iocb->ki_pos, from->ubuf, L_Size, flag, inode_id_temp);
		// printk("********************************************");
		// printk("pass-flag-1\n");
		// printk("flag-1-ret = %ld\n",ret);
#ifdef FLEXIBLE_DIO_WRITE // 采用灵活的 DIO 写入策略：中间页原本会走 directIO，现在判定如果页数小于等于 2，则中间页直接走 bladeIO
		const size_t MID_PAGE_NUM_THRESHOLD = dio_page_num; // 中间页会直接走 bladeIO 的阈值

		const size_t mid_page_num = (from->count - L_Size - R_Size) / Aligned_Size;
		if(mid_page_num <= MID_PAGE_NUM_THRESHOLD){ // 小于阈值，中间满页走 blade IO
			for(int i = 0;i < mid_page_num;i++){
				size_t offset = L_Size + i * Aligned_Size;
				ssize_t ret = xxfs_bio_write(iocb->ki_pos + offset, from->ubuf + offset, Aligned_Size, 5, inode_id_temp);
			}
			D_flag = FALSE;
		}
		// 大于阈值，无事发生，继续执行原先的逻辑
#endif


		// copy from user
		if(L_Size == ocount)
			goto io_done;
		// printk("********************************************");
	}
	else if(L_Size == 0){
		flag = 2;
#ifdef FLEXIBLE_DIO_WRITE // 采用灵活的 DIO 写入策略：中间页原本会走 directIO，现在判定如果页数小于等于 2，则中间页直接走 bladeIO
		const size_t MID_PAGE_NUM_THRESHOLD = dio_page_num; // 中间页会直接走 bladeIO 的阈值

		const size_t mid_page_num = (from->count - L_Size - R_Size) / Aligned_Size;
		if(mid_page_num <= MID_PAGE_NUM_THRESHOLD){ // 小于阈值，中间满页走 blade IO
			for(int i = 0;i < mid_page_num;i++){
				size_t offset = L_Size + i * Aligned_Size;
				ssize_t ret = xxfs_bio_write(iocb->ki_pos + offset, from->ubuf + offset, Aligned_Size, 5, inode_id_temp);
			}
			D_flag = FALSE;
		}
		// 大于阈值，无事发生，继续执行原先的逻辑
#endif
		// printk("[INFO]: come in-flag-2\n");
		ret = xxfs_bio_write(iocb->ki_pos + from->count - R_Size, from->ubuf + from->count - R_Size, R_Size, flag, inode_id_temp);
		// printk("********************************************\n");
		// printk("pass-flag-2\n");
		// printk("flag-2-ret = %ld\n",ret);
		// printk("********************************************\n");
	}
	else if(L_Size + R_Size == from->count){//  ?
		flag = 3;
		// printk("********************************************\n");
		// printk("come in-flag-3\n");
		// printk("[INFO]: come in-flag-3\n");
		ret = xxfs_bio_write(iocb->ki_pos, from->ubuf, L_Size + R_Size, flag, inode_id_temp);
		// printk("********************************************\n");
		// printk("pass-flag-3\n");
		// printk("flag-3-ret = %ld\n",ret);
		// printk("********************************************\n");


		// copy from user
		goto io_done;
	}
	else{
		flag = 4;
		// printk("[INFO]: come in-flag-4\n");
		ret = xxfs_bio_write(iocb->ki_pos, from->ubuf, L_Size, flag, inode_id_temp);
#ifdef FLEXIBLE_DIO_WRITE // 采用灵活的 DIO 写入策略：中间页原本会走 directIO，现在判定如果页数小于等于 2，则中间页直接走 bladeIO
		const size_t MID_PAGE_NUM_THRESHOLD = dio_page_num; // 中间页会直接走 bladeIO 的阈值

		const size_t mid_page_num = (from->count - L_Size - R_Size) / Aligned_Size;
		if(mid_page_num <= MID_PAGE_NUM_THRESHOLD){ // 小于阈值，中间满页走 blade IO
			for(int i = 0;i < mid_page_num;i++){
				size_t offset = L_Size + i * Aligned_Size;
				ssize_t ret = xxfs_bio_write(iocb->ki_pos + offset, from->ubuf + offset, Aligned_Size, 5, inode_id_temp);
			}
			D_flag = FALSE;
		}
		// 大于阈值，无事发生，继续执行原先的逻辑
#endif
		ret += xxfs_bio_write(iocb->ki_pos + from->count - R_Size, from->ubuf + from->count - R_Size, R_Size, flag, inode_id_temp);
		// printk("********************************************\n");
		// printk("pass-flag-4\n");
		// printk("flag-4-ret = %ld\n",ret);
		// printk("********************************************\n");
	}

	// void *dio_buf = kvalloc(sizeof(from->ubuf) - L_Size - R_Size);
	// memcpy(from->ubuf + L_Size,dio_buf,from->count - L_Size - R_Size);

	// iocb->ki_pos = iocb->ki_pos - L_Size;
	// from->ubuf = dio_buf;


// #ifdef FLEXIBLE_DIO_WRITE // 采用灵活的 DIO 写入策略：中间页原本会走 directIO，现在判定如果页数小于等于 2，则中间页直接走 bladeIO
// 	const size_t MID_PAGE_NUM_THRESHOLD = 4; // 中间页会直接走 bladeIO 的阈值

// 	const size_t mid_page_num = (from->count - L_Size - R_Size) / Aligned_Size;
// 	if(mid_page_num <= MID_PAGE_NUM_THRESHOLD){ // 小于阈值，中间满页走 blade IO
// 		for(int i = 0;i < mid_page_num;i++){
// 			size_t offset = L_Size + i * Aligned_Size;
// 			ssize_t ret = xxfs_bio_write(iocb->ki_pos + offset, from->ubuf + offset, Aligned_Size, 5, inode_id_temp);
// 		}
// 		return RET;
// 	}
// 	// 大于阈值，无事发生，继续执行原先的逻辑
// #endif
	
	if(!D_flag){
		size_t copyret = copy_from_user((char *)(allpage_data) + 1ll * mymax(0, blade_page_pos - 5) * Aligned_Size + iocb->ki_pos % Aligned_Size, (char *)from->ubuf, from->count);
		sum_copy_from_user_bytes += from->count - copyret;
		sum_failed_copy_from_user_bytes += copyret;
		return RET;
	}

	// 拷贝两边的数据
	if(L_Size > 0){
		size_t Lcopyret = copy_from_user((char *)(allpage_data) + 1ll * mymax(0, blade_page_pos - 5) * Aligned_Size + iocb->ki_pos % Aligned_Size, (char *)from->ubuf, L_Size);
		sum_copy_from_user_bytes += L_Size - Lcopyret;
		sum_failed_copy_from_user_bytes += Lcopyret;
	}
	if(R_Size > 0){
		size_t Rcopyret = copy_from_user((char *)(allpage_data) + 1ll * mymax(0, blade_page_pos - 5) * Aligned_Size + iocb->ki_pos % Aligned_Size + from->count - R_Size, (char *)from->ubuf + from->count - R_Size, R_Size);
		sum_copy_from_user_bytes += R_Size - Rcopyret;
		sum_failed_copy_from_user_bytes += Rcopyret;
	}


	// 更新 dio_write_opt_num 和 dio_write_page_num
	dio_write_opt_num += 1;
	dio_write_page_num += (from->count - L_Size - R_Size) / Aligned_Size;

#ifdef CALCULATE_STORAGE_PERCENT
	if(from->count < 4ll * 1024 * 1024){
		sum_write_bytes += from->count;
		sum_storage_bytes += from->count - L_Size - R_Size;
		sum_storage_bytes_include_delete += from->count - L_Size - R_Size;
	}
#endif


	sum_write_bytes += from->count;

	// 获取第一个 iovec，并确定用户空间缓冲区的起始地址和大小
	// printk("********************************************\n");
	// printk("buf_size = %ld, L_Size = %ld, R_Size = %ld\n",buf_size,L_Size,R_Size);
	// printk("********************************************\n");

	// if (!access_ok(from->ubuf, buf_size)) {
	// // printk("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\n");
    // // printk(KERN_ERR "Invalid user space address: from->ubuf=%p, buf_size=%zu\n", from->ubuf, buf_size);
    // return -EFAULT;
	// }

	// 分配大小为 buf_size - L_Size - R_Size 的缓冲区
	// start_diobuf = ktime_get();
	size_t buf_size = iov_iter_count(from);
	struct kvec kvec;
	kvec.iov_len = buf_size - L_Size - R_Size;

#ifdef STATIC_WRITE_ITER_DIO_BUF

	int goat_write_iter_dio_buf_idx = 0;
#ifdef USING_LOCK
	spin_lock(&write_iter_dio_buf_lock);
#endif
	for(int i = 0;i < WriteIterDIOBufNum;i++){
		if(write_iter_dio_buf_used[i] == FALSE){
			goat_write_iter_dio_buf_idx = i;
			write_iter_dio_buf_used[i] = TRUE;
			break;
		}
	}
	// while(1){
	// 	int random_idx = get_random_num(0,WriteIterDIOBufNum - 1);
	// 	if(write_iter_dio_buf_used[random_idx] == FALSE){
	// 		goat_write_iter_dio_buf_idx = random_idx;
	// 		write_iter_dio_buf_used[random_idx] = TRUE;
	// 		break;
	// 	}
	// }
#ifdef USING_LOCK
	spin_unlock(&write_iter_dio_buf_lock);
#endif
	max_dio_buf_len = mymax(max_dio_buf_len, buf_size - L_Size - R_Size);
	// size_t size1 = (buf_size - L_Size - R_Size) / 2;
	// size_t size2 = (buf_size - L_Size - R_Size) - size1;
	size_t copyret = copy_from_user((char*)write_iter_dio_buf[goat_write_iter_dio_buf_idx], (char*)(from->ubuf) + L_Size, buf_size - L_Size - R_Size);
	sum_copy_from_user_bytes += buf_size - L_Size - R_Size - copyret;
	sum_failed_copy_from_user_bytes += copyret;
	// const size_t copy_per_size = 1ll * 1024 * 1024; // 每次拷贝的长度
	// const size_t copy_times = (buf_size - L_Size - R_Size) / copy_per_size; // 拷贝次数
	// for(int i = 0;i < copy_times;i++){
	// 	size_t copyret = copy_from_user((char*)write_iter_dio_buf[goat_write_iter_dio_buf_idx] + i * copy_per_size, (char*)(from->ubuf) + L_Size + i * copy_per_size, copy_per_size);
	// 	if(copyret != 0){
	// 		printk("[DIO BUF COPY]: copy_from_user ERROR! copyret = %ld\n", copyret);
	// 	}
	// }
	// if((buf_size - L_Size - R_Size) % copy_per_size){
	// 	size_t copyret = copy_from_user((char*)write_iter_dio_buf[goat_write_iter_dio_buf_idx] + copy_times * copy_per_size, (char*)(from->ubuf) + L_Size + copy_times * copy_per_size, (buf_size - L_Size - R_Size) % copy_per_size);
	// 	if(copyret != 0){
	// 		printk("[DIO BUF COPY]: copy_from_user ERROR! copyret = %ld\n", copyret);
	// 	}
	// }

	// copy_from_user((char*)write_iter_dio_buf[goat_write_iter_dio_buf_idx], (char*)(from->ubuf) + L_Size, size1);
	// copy_from_user((char*)write_iter_dio_buf[goat_write_iter_dio_buf_idx] + size1, (char*)(from->ubuf) + L_Size + size1, size2);
	// if(copyret != 0){
	// 	printk("[DIO BUF COPY]: copy_from_user ERROR! copyret = %ld\n", copyret);
	// }
	kvec.iov_base = write_iter_dio_buf[goat_write_iter_dio_buf_idx];

#else
	void *dio_buf = vmalloc(buf_size - L_Size - R_Size);
	copy_from_user((char*)dio_buf, (char*)(from->ubuf) + L_Size, buf_size - L_Size - R_Size);
	kvec.iov_base = dio_buf;
#endif
	// kvec.iov_base = write_iter_dio_buf[goat_write_iter_dio_buf_idx];
	
	// end_diobuf = ktime_get();
	// s64 elapsed_diobuf_ns = ktime_to_ns(ktime_sub(end_diobuf,start_diobuf));
	// printk("elapsed_diobuf = %ld ns\n",elapsed_diobuf_ns);

	// if(dio_buf == NULL){
	// 	dio_buf = vmalloc(1ll*1024*1024*1024);
	// 	// printk("********************************************\n");
	// 	// printk("fault-dio_buf-wrong!!!!!!!!! ");
	// 	// printk("********************************************\n");
	//  }
	// memcpy(from->ubuf + L_Size,dio_buf,from->count - L_Size - R_Size);

	// 从用户空间复制数据到内核缓冲区
	// if (copy_from_user((char*)dio_buf, (char*)(from->ubuf + L_Size), buf_size - L_Size - R_Size)) {
    // 	// printk(KERN_ERR "Failed to copy data from user space\n");
    // 	return -EFAULT;
	// }
	// start_copy = ktime_get();
	
	

	// write_iter_dio_buf size = 20M
	// copy_from_user((char*)write_iter_dio_buf[goat_write_iter_dio_buf_idx], (char*)(from->ubuf) + L_Size, buf_size - L_Size - R_Size);

	// end_copy = ktime_get();
	// s64 elapsed_copy_ns = ktime_to_ns(ktime_sub(end_copy,start_copy));
	// printk("elapsed_copy = %ld ns\n",elapsed_copy_ns);


	
	// printk("!!!!!!!!!!!!!!!!\n");
	// printk("diobuf = %s",(char*)dio_buf);

	// 定义 kvec，指向 dio_buf
	// if(kvec.iov_len%Aligned_Size != 0){
	// 	printk("L_Size = %ld, R_Size = %ld\n",L_Size,R_Size);
	// 	printk("buf_size = %ld L_Size+R_Size+len = %ld",buf_size,L_Size+R_Size+kvec.iov_len);
	// 	printk("ggggggggggggggggggggggggg\n");
	// }
	// printk(KERN_ERR "kvec.iov_len = %ld\n", kvec.iov_len);
	// start_ioviter = ktime_get();
	// 初始化新的 iov_iter，类型为 ITER_KVEC
	struct iov_iter iter;
	iov_iter_kvec(&iter, from->data_source, &kvec, from->nr_segs, kvec.iov_len);
	/*
	void iov_iter_kvec(struct iov_iter *i, unsigned int direction,
			const struct kvec *kvec, unsigned long nr_segs,
			size_t count)
	{
		WARN_ON(direction & ~(READ | WRITE));
		*i = (struct iov_iter){
			.iter_type = ITER_KVEC,
			.data_source = direction,
			.kvec = kvec,
			.nr_segs = nr_segs,
			.iov_offset = 0,
			.count = count
		};
	}
EXPORT_SYMBOL(iov_iter_kvec);
*/ 
	// 调整 iocb->ki_pos，更新用户空间缓冲区指针
	iocb->ki_pos = iocb->ki_pos + L_Size;
	if(iocb->ki_pos%Aligned_Size != 0){
		size_t mynum = iocb->ki_pos%Aligned_Size;
		// printk("ggggggggggggggggggggggggg\n");
		// printk("iocb->ki_pos alignedsize == %ld\n",mynum);
		// printk("ggggggggggggggggggggggggg\n");

	}
	// from->ubuf = (void __user*)dio_buf;
	// iov_iter_ubuf(from, from->data_source, dio_buf, from->count);

	from->count = from->count - L_Size - R_Size;

	// copy_to_user((void __user *)(from->ubuf + L_Size), (char *)dio_buf, buf_size - L_Size - R_Size);
	// end_ioviter = ktime_get();
	// s64 elapsed_ioviter = ktime_to_ns(ktime_sub(end_ioviter,start_ioviter)); 
	// printk("elapsed_ioviter = %ld ns\n",elapsed_ioviter);

	// 更新偏移量和迭代器状态
	// iov_iter_advance(from, buf_size - L_Size - R_Size);
	// iocb->ki_pos += buf_size - L_Size - R_Size;

	// printk("from->count:%d buf_size - L_Size - R_Size:%d\n", from->count, buf_size - L_Size - R_Size);

	// printk("********************************************");
	// printk("diobuf = %s, buf_size = %ld, L_Size = %ld, R_Size = %ld",dio_buf,buf_size,L_Size,R_Size);
	// printk("********************************************");

	// iocb->ki_pos = iocb->ki_pos - L_Size;              
	// from->ubuf = dio_buf;
    unsigned long start_index = iocb->ki_pos / Aligned_Size;
    unsigned long end_index = (iocb->ki_pos + from->count - 1) / Aligned_Size;
    unsigned long num_pages = end_index - start_index + 1;


#ifdef USING_LOCK
	spin_lock(&file_xarray_lock[inode_id_temp]);
#endif

	// printk("[ENTER DELETE]: start_page = %d start_pos = %d end_page = %d end_pos = %d\n", iocb->ki_pos / Aligned_Size, iocb->ki_pos % Aligned_Size ,(iocb->ki_pos + from->count - 1) / Aligned_Size, (iocb->ki_pos + from->count - 1) % Aligned_Size);
	for(unsigned long i = start_index;i <= end_index;i++){
		int nowpage = query_in_xarray(myxa[inode_id_temp], i, inode_id_temp);


		if(nowpage >= 0){

#ifdef CALCULATE_PER4K
			// if(from->count < 4ll * 1024 * 1024){
			// 	int start_page_4k_id = nowpage * Aligned_Size / Size4K;
			// 	int end_page_4k_id = (nowpage * Aligned_Size + Aligned_Size) / Size4K;
			// 	for(int j = start_page_4k_id;j < end_page_4k_id;j++){
			// 		used_page_4k_num -= 1;
			// 		if(allpage_4k[j].sumlen == Size4K){
			// 			full_page_4k_num -= 1;
			// 		}
			// 	}
			// }
#endif

#ifdef CALCULATE_STORAGE_PERCENT
			if(from->count < 4ll * 1024 * 1024){
				for(int j = 0;j < allpage_meta[nowpage].num;j++){
					sum_storage_bytes_include_delete += allpage_meta[nowpage].len[j];
				}
			}
#endif
			delete_in_xarray(myxa[inode_id_temp], i, inode_id_temp);		
#ifdef USING_LOCK
			spin_lock(&bitmap_lock[0]);
#endif
			blade_page_bitmap[nowpage] = 0;
			using_page_num -= 1;
#ifdef USING_LOCK
			spin_unlock(&bitmap_lock[0]);
#endif
#ifdef DOFLUSH
// 			atomic64_sub(Aligned_Size, &page_used_size); // 暂定这么写
#endif
		}
	}


#ifdef USING_LOCK
	spin_unlock(&file_xarray_lock[inode_id_temp]);
#endif
	

	if (iocb->ki_flags & IOCB_DIRECT) 
	{
		/*
		 * Allow a directio write to fall back to a buffered
		 * write *only* in the case that we're doing a reflink
		 * CoW.  In all other directio scenarios we do not
		 * allow an operation to fall back to buffered mode.
		 */
		// printk("retreterertertertertertertertertertert\n");
		// start_diowrite = ktime_get();
		// printk("from status:\n");
		// print_iov_iter(from);
		// printk("kvec iter status:\n");
		// print_iov_iter(&iter);
		// tmp = xfs_file_dio_write(iocb, from);

#ifdef DOFLUSH
		// size_t st = iocb->ki_pos / Chunk_Size;
		// size_t ed = (iocb->ki_pos + from->count - 1) / Chunk_Size;
		// for(size_t i = st;i <= ed;i++){
		// 	atomic_inc(&SSD_task_num[i % FLUSH_THREAD_NUM]); 
		// }
#endif
		// printk("[DIO WRITE]: dio write!");
		// ssize_t tmp = 0;
		ssize_t tmp = xfs_file_dio_write(iocb, &iter);

#ifdef STATIC_WRITE_ITER_DIO_BUF

#ifdef USING_LOCK
		spin_lock(&write_iter_dio_buf_lock);
#endif
		write_iter_dio_buf_used[goat_write_iter_dio_buf_idx] = FALSE;
#ifdef USING_LOCK
		spin_unlock(&write_iter_dio_buf_lock);
#endif

#endif

#ifdef DOFLUSH
		// for(size_t i = st;i <= ed;i++){
		// 	atomic_dec(&SSD_task_num[i % FLUSH_THREAD_NUM]); 
		// }
#endif
		// atomic_inc(&SSD_task_num[0]); 
		// tmp = xfs_file_dio_write(iocb, &iter);
		// atomic_dec(&SSD_task_num[0]); 


		// end_diowrite = ktime_get();
		// s64 elapsed_diowrite = ktime_to_ns(ktime_sub(end_diowrite,start_diowrite));
		// sum_dio_write += elapsed_diowrite;
		// printk("elapsed_diowrite = %ld ns\n",elapsed_diowrite);
		// ASSERT(1==0);
		// end_all = ktime_get();
		
		// s64 elapsed_ns = ktime_to_ns(ktime_sub(end_all,start_all));
		// double elapsed_sec = elapsed_ns*1.0 / 1000000000LL;
		// sum += elapsed_ns;
		// printk("start_all = %ld ns\n",start_all);
		// printk("end_all = %ld ns\n",end_all);
		// printk("elapsed time = %ld ns\n", elapsed_ns);
		// printk("sum = %ld\n",sum);
		// printk("dio_write ret = %ld\n",tmp);

#ifndef STATIC_WRITE_ITER_DIO_BUF
		vfree(dio_buf);
#endif


		if (tmp != -ENOTBLK)
			return RET;
		// if (ret != -ENOTBLK)
		// 	return ret;
	}

io_done:
	// return ret;
	if(!D_flag){
		size_t copyret = copy_from_user((char *)(allpage_data) + 1ll * mymax(0, blade_page_pos - 5) * Aligned_Size + iocb->ki_pos % Aligned_Size, (char *)from->ubuf, from->count);
		sum_copy_from_user_bytes += from->count - copyret;
		sum_failed_copy_from_user_bytes += copyret;
	}
	else {
		// 拷贝两边的数据
		if(L_Size > 0){
			size_t Lcopyret = copy_from_user((char *)(allpage_data) + 1ll * mymax(0, blade_page_pos - 5) * Aligned_Size + iocb->ki_pos % Aligned_Size, (char *)from->ubuf, L_Size);
			sum_copy_from_user_bytes += L_Size - Lcopyret;
			sum_failed_copy_from_user_bytes += Lcopyret;
		}
		if(R_Size > 0){
			size_t Rcopyret = copy_from_user((char *)(allpage_data) + 1ll * mymax(0, blade_page_pos - 5) * Aligned_Size + iocb->ki_pos % Aligned_Size + from->count - R_Size, (char *)from->ubuf + from->count - R_Size, R_Size);
			sum_copy_from_user_bytes += R_Size - Rcopyret;
			sum_failed_copy_from_user_bytes += Rcopyret;
		}
	}

	return RET;
	
#endif


	if (iocb->ki_flags & IOCB_DIRECT) {
		/*
		 * Allow a directio write to fall back to a buffered
		 * write *only* in the case that we're doing a reflink
		 * CoW.  In all other directio scenarios we do not
		 * allow an operation to fall back to buffered mode.
		 */
		// printk("rettertertertertertertertertrertrertertertertert\n");
		// printk("[DIO WRITE]: dio write!");
		ret = xfs_file_dio_write(iocb, from);
		
		if (ret != -ENOTBLK)
			return ret;
	}

	return xfs_file_buffered_write(iocb, from);
}
#else
STATIC ssize_t
xfs_file_write_iter(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	// iocb 一次文件IO操作 包含文件指针、偏移量等
	struct inode		*inode = iocb->ki_filp->f_mapping->host; // 获取文件inode
	// ki_flip 指向文件描述符的指针，代表一个打开的文件(struct file)。每个打开的文件都与一个file结构相关联
	// f_mapping 是struct file中的一个成员,指向address_space 代表文件内容在内存中的映射，用于管理文在页缓存中的映射。
	// host 是struct address_space中的一个成员，指向struct inode. 存储了文件或目录的元数据。
	
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;
	size_t			ocount = iov_iter_count(from);

	XFS_STATS_INC(ip->i_mount, xs_write_calls);

#ifdef XFS_PRINTK
	printk("write /mnt/xfstest/%ld %ld %ld\n", XFS_I(inode)->i_ino, iocb->ki_pos, from->count);
#endif

	if (ocount == 0)
		return 0;

	if (xfs_is_shutdown(ip->i_mount))
		return -EIO;

	if (IS_DAX(inode))
		return xfs_file_dax_write(iocb, from);

	if (iocb->ki_flags & IOCB_DIRECT) {
		/*
		 * Allow a directio write to fall back to a buffered
		 * write *only* in the case that we're doing a reflink
		 * CoW.  In all other directio scenarios we do not
		 * allow an operation to fall back to buffered mode.
		 */
		ret = xfs_file_dio_write(iocb, from);
		if (ret != -ENOTBLK)
			return ret;
	}

	return xfs_file_buffered_write(iocb, from);
}
#endif



struct timespec64 t1,t2;

#ifdef XXFS
STATIC ssize_t
xfs_file_read_iter(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	// if(allpage == NULL){
	// allpage = memorycache;
	// }
	struct inode		*inode = file_inode(iocb->ki_filp);
	struct xfs_mount	*mp = XFS_I(inode)->i_mount;
	ssize_t			ret = 0;
	ssize_t  RET = 0;
	ssize_t initial_ki_pos = iocb->ki_pos;
	ssize_t initial_to_count = to->count;
	ssize_t buf_read_ret = 0, blade_read_ret = 0;
	
	XFS_STATS_INC(mp, xs_read_calls);

	if (xfs_is_shutdown(mp))
		return -EIO;


	// printk("[READ ITER]: iocb->ki_pos = %ld len = %ld inode = %ld filelen = %ld", iocb->ki_pos, to->count, XFS_I(inode)->i_ino,inode->i_size);
// 	if(to->count == 4096ll * 1024 + 666){
// 		ssize_t calculate_offset = 0;
// #ifdef CALCULATE_PER4K
// 		copy_to_user(to->ubuf + calculate_offset, &used_page_4k_num, sizeof(ssize_t));
// 		calculate_offset += sizeof(ssize_t);
// 		copy_to_user(to->ubuf + calculate_offset, &full_page_4k_num, sizeof(ssize_t));
// 		calculate_offset += sizeof(ssize_t);
// #endif

// #ifdef CALCULATE_STORAGE_PERCENT
// 		copy_to_user(to->ubuf + calculate_offset, &sum_storage_bytes, sizeof(ssize_t));
// 		calculate_offset += sizeof(ssize_t);
// 		copy_to_user(to->ubuf + calculate_offset, &sum_storage_bytes_include_delete, sizeof(ssize_t));
// 		calculate_offset += sizeof(ssize_t);
// 		copy_to_user(to->ubuf + calculate_offset, &sum_write_bytes, sizeof(ssize_t));
// 		calculate_offset += sizeof(ssize_t);
// #endif
// 		copy_to_user(to->ubuf + calculate_offset, &write_iter_opt, sizeof(ssize_t));
// 		calculate_offset += sizeof(ssize_t);
// 		return RET;
// 	}



#ifdef XXFS
	// printk("111111111111111111111\n");
#ifdef MYDEBUG
	printk("[BEGIN READ]: ----------------------------------------------------------------\n");
#endif

	// printk("[READ ITER]: inode = %ld", XFS_I(inode)->i_ino);

	// 插入文件 inode 号记录
	// update_in_xarray(file_inode_xa, XFS_I(inode)->i_ino, 1);

	// t++;
	// if(t <= 1) traverse_allpage_blade_io_info();
	size_t xaid = get_hashcode(XFS_I(inode)->i_ino);

	// 检测哈希碰撞
	if(xarray_hash_code_table[xaid] == -1){ // 未记录
		xarray_hash_code_table[xaid] = XFS_I(inode)->i_ino;
	}
	else if(xarray_hash_code_table[xaid] != XFS_I(inode)->i_ino){ // 已经记录过，并且不相等，说明发生了哈希碰撞
		printk("[READ ITER XARRAY HASH COLLISION]: collision_code = %ld. recorded_num = %ld, new_num = %ld\n", xaid, xarray_hash_code_table[xaid], XFS_I(inode)->i_ino);
	}

	// printk("xaid = %ld\n",xaid);
	ASSERT(xaid);

#ifdef DOFLUSH
	if(to->count == 9ll * 1024 * 1024 + 4096){
#ifndef ONLY_FLUSH
		set_now_time(&now_time);
		// 距离上次实际 IO 时间超过 1s，且距离挂载时间超过 1s，打印内核状态
		if(get_time_diff_nsec(&last_real_io_time, &now_time) > TIME_MSEC_TO_NSEC(1000) && get_time_diff_nsec(&mount_time, &now_time) > TIME_MSEC_TO_NSEC(8000)){
			if(print_kernel_state_opt <= 30){
				print_kernel_state();
			}
		}
		int wait_num = 0;
		// printk("[DO READSSD]: enter deep copy.");
		// deep copy
		deep_copy_kiocb(iocb,&(readssd_io_info->iocb));
		// printk("[READ ITER]: deep copy kiocb time = %ld ns\n",get_time_diff_nsec(&t1,&t2));
		// deep_copy_iov_iter(to,&(readssd_io_info->iter),TRUE);
		// readssd_io_info->iocb->ki_flags = 0; // 经测试，读操作的 ki_flags 为 0
		// readssd_io_info->iter->data_source = READ; // 设置为读操作
		readssd_io_info->iocb->ki_flags |= IOCB_DIRECT; // 设置为直接IO

		// printk("[DO READSSD]: successfully deep copy. prepare to read from ssd.");

		atomic64_set(&flush_read_blocked, 1);

		while(atomic64_read(&flush_read_blocked) == 1 && wait_num < 100000){
			wait_num++;
			// udelay(50);
			usleep_range(10,15);
		}
#endif

		return RET;
	}
#endif
	sum_read_bytes += to->count;

	set_now_time(&last_real_io_time);

	if(is_zero_time(&first_rw_time) == TRUE){
		set_now_time(&first_rw_time);
	}


	// if (myxa_val[ip->i_ino] == 0) {
    // init_xarray(&myxa[ip->i_ino]);  // 初始化 xarray
    // if (!myxa[ip->i_ino]) {
    //     // printk(KERN_ERR "Failed to initialize xarray for inode %llu\n", ip->i_ino);
    //     return -ENOMEM;
    // 	}
    // myxa_val[ip->i_ino] = 1;
	// }
	// printk("before init myxa_val[xaid] = %ld\n",myxa_val[xaid]);
	// int blg_idx = -1;

	// spin_lock(&blg_lock);

	// for(int i = 0;i < blg_ed;i++){
	// 	if(blg[i] == XFS_I(inode)->i_ino){
	// 		blg_idx = i;
	// 		break;
	// 	}
	// }

	// if(blg_idx == -1){
	// 	blg_idx = blg_ed;
	// 	blg[ blg_ed++ ] = XFS_I(inode)->i_ino;
	// }

	// xaid = blg_idx;

	// spin_unlock(&blg_lock);

	if(myxa_val[xaid]==0){
		// printk("[WIRTE ITER]: init xarray not int mount. xaid = %ld\n", xaid);
		// printk("[INIT XARRAY]: init xarray for inode %ld\n",xaid);
		init_xarray(&myxa[xaid]);
		if(!myxa[xaid]){
			// printk(KERN_ERR "Failed to initialize xarray for inode %llu\n",xaid);
			return -ENOMEM;
		}
		myxa_val[xaid]=1;
	}
	// printk("after myxa_val[xaid] = %ld\n",myxa_val[xaid]);
	// printk("22222222222222222222222\n");

	// if(readssd_io_info->iocb == NULL && readssd_io_info->iter == NULL){
	// 	printk("[READ SSD IO INFO]: enter read ssd io info!");
	// 	show_time();
	// 	// 深拷贝 iocb
	// 	// 深拷贝 iov_iter
		
	// 	deep_copy_kiocb(iocb,&(readssd_io_info->iocb));
	// 	deep_copy_iov_iter(to,&(readssd_io_info->iter),TRUE);

	// 	// readssd_io_info->iocb = (struct kiocb *)vmalloc(sizeof(struct kiocb));
	// 	// readssd_io_info->iter = (struct iov_iter *)vmalloc(sizeof(struct iov_iter));

	// 	// memcpy(readssd_io_info->iocb, iocb, sizeof(struct kiocb));
	// 	// memcpy(readssd_io_info->iter, to, sizeof(struct iov_iter));


	// 	// readssd_io_info->iocb->ki_flags = 0;
	// 	// readssd_io_info->iter->data_source = READ; // 设置为读操作

	// 	// readssd_io_info->iter->count = 1024;
	// 	ssize_t ret = xfs_file_buffered_read(readssd_io_info->iocb,readssd_io_info->iter);
	// 	// ssize_t ret = xfs_file_buffered_read(iocb,to);
	// 	if(ret <= 0){
	// 		printk("[READ FROM SSD]: read_from_SSD failed! return ret = %lld.\n", ret);
	// 	}
	// 	else{
	// 		printk("[READ FROM SSD]: read_from_SSD successfully! read %lld bytes.\n", ret);
	// 	}
	// }

	

    loff_t pos = iocb->ki_pos;
    loff_t start_pos = pos;
	size_t count = iov_iter_count(to);
    loff_t end_pos = pos + count - 1;
	// loff_t end_pos = pos + count;
    

    //io_request blade_io[MAX_IO];
	// io_request *blade_io = vmalloc(1000 * sizeof(io_request));
    int num_blade_io = 0;

	io_request *blade_io = static_blade_io[0];
	int goat_blade_io_idx = 0;
#ifdef STATIC_BLADE_IO

#ifdef USING_LOCK
	spin_lock(&static_blade_io_lock);
#endif
	for(int i = 0;i < USER_THREAD_NUM;i++){
		if(static_blade_io_used[i] == FALSE){
			blade_io = static_blade_io[i];
			goat_blade_io_idx = i;
			static_blade_io_used[i] = TRUE;
			break;
		}
	}
#ifdef USING_LOCK
	spin_unlock(&static_blade_io_lock);
#endif

#endif

    // io_request buffered_io[MAX_IO];
    // int num_buffered_io = 0;
    // int i;

    //step1 
    unsigned long start_index = start_pos / Aligned_Size;
    unsigned long end_index = end_pos / Aligned_Size;
    unsigned long num_pages = end_index - start_index + 1;

	// printk("start_index = %ld\n",start_index);
	// printk("end_index = %ld\n",end_index);
	// printk("num_pages = %ld\n",num_pages);
	// int *range_query_result = (int *)vmalloc(1000 * sizeof(int));

	long long *range_query_result = static_range_query_result[0];
	int goat_range_query_result_idx = 0;
#ifdef STATIC_RANGE_QUERY_RESULT

#ifdef USING_LOCK
	spin_lock(&static_range_query_result_lock);
#endif
	for(int i = 0;i < USER_THREAD_NUM;i++){
		if(static_range_query_result_used[i] == FALSE){
			range_query_result = static_range_query_result[i];
			goat_range_query_result_idx = i;
			static_range_query_result_used[i] = TRUE;
			break;
		}
	}
#ifdef USING_LOCK
	spin_unlock(&static_range_query_result_lock);
#endif

#endif

	// traverse_in_xarray(myxa[xaid]);

// #define DEBUG
#ifdef MYDEBUG
	printk("[RANGE_QUERY]: start_index = %ld, end_index = %ld\n", start_index, end_index);
#endif
	// int ret_query = 0;
    int ret_query = range_query_in_xarray_nlogn(myxa[xaid], start_index, end_index, range_query_result, xaid);//query_in_xarray考虑改成范围查找，对应参数可能要改。用于找到所有的可能的blade page，下标放在range_query_result里面。
	max_range_query_result_num = mymax(max_range_query_result_num, ret_query);
    // printk("ret_query = %d\n",ret_query);
	if(ret_query == 0)
        goto bio_only;
	ASSERT(ret_query>0);


	// printk("[range_query_result] : (size = %d) ",num_pages);
	// for(int i = 0;i < num_pages;i++){
	// 	printk(KERN_CONT "%d ",range_query_result[i]);
	// 	if(range_query_result[i] == -1) continue;
	// 	traverse_allpage_bladeIO(range_query_result[i]);
	// }
	

	//do_select
	//扫一遍所有的blade page，把blade IO拎出来，剩余的自然就是buffered IO
	unsigned long firstpage = range_query_result[0];
	unsigned long endpage = range_query_result[num_pages-1];

	// // 输出 range_query_result 的信息
	// printk("[range_query_result] : (size = %d) ",num_pages);
	// for(int i = 0;i < num_pages;i++){
	// 	printk(KERN_CONT "%d ",range_query_result[i]);
	// }
	// 输出每个查询到的页里面的所有 IO 请求
	// for(int i = 0;i < num_pages;i++){
	// 	// printk("[page_io_segment](range_query_result_id,startpos,endpos) : ");
	// 	if(range_query_result[i] == -1){
	// 		printk("range_query_result == -1, index = %d num_pages = %d", i,num_pages);
	// 	}
	// 	// for(int j = 0;j < allpage_meta[range_query_result[i]].num;j++){
	// 	// 	printk(KERN_CONT "(%d,%d,%d) ",range_query_result[i],allpage_meta[range_query_result[i]].pos[j],allpage_meta[range_query_result[i]].pos[j] + allpage_meta[range_query_result[i]].len[j] - 1);
	// 	// }
	// 	// printk(KERN_CONT "\n");
	// }

#ifdef MYDEBUG
	// 输出 range_query_result 的信息
	printk("[range_query_result] : (size = %d) ",num_pages);
	for(int i = 0;i < num_pages;i++){
		printk(KERN_CONT "%d ",range_query_result[i]);
	}
	// 输出每个查询到的页里面的所有 IO 请求
	for(int i = 0;i < num_pages;i++){
		printk("[page_io_segment](range_query_result_id,startpos,endpos) : ");
		if(range_query_result[i] == -1) continue;
		for(int j = 0;j < allpage[range_query_result[i]].num;j++){
			printk(KERN_CONT "(%d,%d,%d) ",range_query_result[i],allpage[range_query_result[i]].pos[j],allpage[range_query_result[i]].pos[j] + allpage[range_query_result[i]].len[j] - 1);
		}
		printk(KERN_CONT "\n");
	}
	// 输出当前的 start_pos 和 end_pos 信息
	printk("[current_read_requests_segment] : (start_page_id = %d,start_pos = %d,end_page_id = %d,end_pos = %d)\n",start_index, start_pos%Aligned_Size, end_index, (end_pos%Aligned_Size));
#endif


	// int flag = 0 ;
	// if(firstpage != -1) 
	// for(int i = 0;i < allpage[firstpage].num; i++) // ！！
	// {

	// 	if(flag == 0 && allpage[firstpage].pos[i]+allpage[firstpage].len[i]>=start_pos%Aligned_Size)
	// 	{
	// 		blade_io[num_blade_io++] = (io_request){firstpage,0,mymax(start_pos%Aligned_Size,allpage[firstpage].pos[i]), mymin(allpage[firstpage].pos[i] + allpage[firstpage].len[i],end_pos)allpage[firstpage].pos[i]+allpage[firstpage].len[i] - start_pos%Aligned_Size};
	// 		flag=1;
	// 		continue;
	// 	}
	// 	if(flag==1)
	// 	{
	// 		if(allpage[firstpage].pos[i] < end_pos % Aligned_Size){
	// 			blade_io[num_blade_io++] = (io_request){firstpage,0,allpage[firstpage].pos[i], mymin(allpage[firstpage].len[i],end_pos%Aligned_Size - allpage[firstpage].pos[i])};
	// 		}
	// 	}
	// }
	// for(int i=1;i<num_pages-1;i++) //  
	// {
	// 	if(range_query_result[i] != -1)
	// 	for(int j=0;j<allpage[range_query_result[i]].num;j++)
	// 	{
	// 		blade_io[num_blade_io++] = (io_request){range_query_result[i],i,allpage[range_query_result[i]].pos[j], mymin(allpage[range_query_result[i]].len[j], end_pos%Aligned_Size - allpage[range_query_result[i]].pos[j])};
	// 	}
	// }
	// if(endpage != -1)
	// for(int i=0;i<allpage[endpage].num;i++)
	// {
	// 	if(allpage[endpage].pos[i] >= end_pos%Aligned_Size){
	// 		break;
	// 	}
	// 	if(allpage[endpage].pos[i]+allpage[endpage].len[i] >= end_pos%Aligned_Size)
	// 	{
	// 		blade_io[num_blade_io++] = (io_request){endpage, num_pages-1, allpage[endpage].pos[i], end_pos - allpage[endpage].pos[i]};
	// 	}
	// 	else {
	// 		blade_io[num_blade_io++] = (io_request){endpage, num_pages-1, allpage[endpage].pos[i], allpage[endpage].len[i]};
	// 	}
	// }

	// 处理第一页
	if(firstpage != -1){
		int posL = start_pos % Aligned_Size;
		int posR = (firstpage == endpage) ? (end_pos % Aligned_Size) : (Aligned_Size - 1);
		if(posR == 0) posR = Aligned_Size - 1;

		// 遍历当前页的所有 IO
		for(int i = 0;i < allpage_meta[firstpage].num;i++){
			// 找到和[posL,posR]有交集的 IO
			if(allpage_meta[firstpage].pos[i] + allpage_meta[firstpage].len[i] - 1 >= posL && allpage_meta[firstpage].pos[i] <= posR){
				blade_io[num_blade_io++] = (io_request){firstpage, 0, mymax(posL,allpage_meta[firstpage].pos[i]), mymin(posR,allpage_meta[firstpage].pos[i] + allpage_meta[firstpage].len[i] - 1) - mymax(posL,allpage_meta[firstpage].pos[i]) + 1};
			}
		}
	}
	// 处理最后一页
	if(endpage != -1 && endpage != firstpage){
		int posL = (firstpage == endpage) ? (start_pos % Aligned_Size) : 0;
		int posR = end_pos % Aligned_Size;
		if(posR == 0) posR = Aligned_Size - 1;

		// 遍历当前页的所有 IO
		for(int i = 0;i < allpage_meta[endpage].num;i++){
			// 找到和[posL,posR]有交集的 IO
			if(allpage_meta[endpage].pos[i] + allpage_meta[endpage].len[i] - 1 >= posL && allpage_meta[endpage].pos[i] <= posR){
				blade_io[num_blade_io++] = (io_request){endpage, num_pages - 1, mymax(posL,allpage_meta[endpage].pos[i]), mymin(posR,allpage_meta[endpage].pos[i] + allpage_meta[endpage].len[i] - 1) - mymax(posL,allpage_meta[endpage].pos[i]) + 1};
			}
		}
	}
	// 处理中间页
	for(int k = 1;k < num_pages - 1;k++){
		int curpage = range_query_result[k];
		if(curpage == -1) continue;

		// 遍历当前页的所有 IO,这些 IO 都是完全覆盖在当前页内的
		for(int i = 0;i < allpage_meta[curpage].num;i++){
			blade_io[num_blade_io++] = (io_request){curpage, k, allpage_meta[curpage].pos[i], allpage_meta[curpage].len[i]};
		}
	}
	max_read_blade_io_num = mymax(max_read_blade_io_num, num_blade_io);


#ifdef MYDEBUG
	// 输出 blade_io 的信息
	printk("[blade_io](pageid,userpageid,startpos,endpos): ");
	for(int i = 0;i < num_blade_io;i++){
		printk(KERN_CONT "(%d,%d,%d,%d) ",blade_io[i].pageid,blade_io[i].userpageid,blade_io[i].pos,blade_io[i].pos + blade_io[i].count - 1);
	}
	printk(KERN_CONT "\n");
#endif
	// 输出 blade_io 的信息
	// printk("[blade_io](pageid,userpageid,startpos,endpos): ");
	// for(int i = 0;i < num_blade_io;i++){
	// 	printk(KERN_CONT "(%d,%d,%d,%d) ",blade_io[i].pageid,blade_io[i].userpageid,blade_io[i].pos,blade_io[i].pos + blade_io[i].count - 1);
	// }
	// printk(KERN_CONT "\n");
	// 输出 blade_io 的信息
	// printk("[blade_io](pageid,userpageid,startpos,endpos): num_blade_io = %d ",num_blade_io);
	// for(int i = 0;i < num_blade_io;i++){
	// 	printk(KERN_CONT "(%d,%d,%d,%d) ",blade_io[i].pageid,blade_io[i].userpageid,blade_io[i].pos,blade_io[i].pos + blade_io[i].count - 1);
	// }
	// printk(KERN_CONT "\n");
	// printk("num_blade_io = %d\n",num_blade_io);
	// int unaligned_num_blade_io = 0;
	// unsigned long all_blade_iosize = 0;
	// for(int i=0;i<num_blade_io;i++)
	// {
	// 	all_blade_iosize + = blade_io[i].len;
	// 	if(blade_io[i].len != Aligned_Size)
	// 		unaligned_num_blade_io++;
	// }

	// char __user * userbuf = to->ubuf;
	// struct iov_iter temp_to;
	// iov_iter_ubuf(&temp_to, to->data_source, to->ubuf, to->count);

	// size_t buf_len = iov_iter_count(to);
	// void  *userbuf = vmalloc(buf_len);
	// copy_from_user((char*)userbuf,(char*)(to->ubuf),buf_len);
	// struct kvec kvec;
	// kvec.iov_base = userbuf;
	// kvec.iov_len = buf_len;
	// struct iov_iter iter;
	// iov_iter_kvec(&iter,to->data_source,&kvec,to->nr_segs,kvec.iov_len);
	// printk("enter for to->ubuf address = %p\n",to->ubuf);

#ifdef NEW_BUFFERED_READ_STRATEGY
	//256KB + 64k = 320K BladeIO < 40% 全读
	//否则，每一页分别看要不要读，只要有不满页的blade IO就要读，头尾记得特判
	//尽可能合并相邻的读
	double read_all_percent = 0.4; // bladeIO 占比小于多少则全读
	int block_page_size_kb = 2048; // 320KB
	int block_page_size = block_page_size_kb * 1024; // 320KB 的具体大小
	int block_page_num = block_page_size / Aligned_Size; // 320KB 有多少个 blade page 页
	if(block_page_size % Aligned_Size != 0){
		printk("block_page_size MOD Aligned_Size != 0\n");
	}

	int *is_page_all_read = (int *)vmalloc(num_pages * sizeof(int)); // 记录每一页是否全读,1表示全读，0表示不全读
	for(int i = 0;i < num_pages;i++){
		is_page_all_read[i] = 0;
	}


	printk("[BUFFERED READ INFO]: begin buffered read. ------------------------------------");
	int cur_page = 0;
	// 处理每一页是否全读
	while(cur_page < num_pages){
		printk("[BUFFERED READ INFO]: In judge buffered read. cur_page = %d num_pages = %d\n",cur_page,num_pages);
		// 特殊情况：只有一页
		if(num_pages == 1){
			int sumLength = end_pos - start_pos; // IO 请求总长度
			int sumIOLength = 0; // bladeIO 请求的总长度
			for(int k = 0;k < num_blade_io;k++){
				if(blade_io[k].userpageid == cur_page){
					sumIOLength += blade_io[k].count;
				}
			}
			is_page_all_read[cur_page] = (sumIOLength < sumLength) ? 1 : 0;
			break;
		}

		// 处理第一页
		if(cur_page == 0){
			// 如果第一页不满则全读，注意是从 start_pos 开始
			int sumLength = Aligned_Size - start_pos % Aligned_Size; // 第一页的 IO 请求总长度
			int sumIOLength = 0; // 第一页的 bladeIO 请求的总长度
			for(int k = 0;k < num_blade_io;k++){
				if(blade_io[k].userpageid == cur_page){
					sumIOLength += blade_io[k].count;
				}
			}
			// 不会出现 bladeIO 起点小于 start_pos 的情况,前面代码已经保证了
			is_page_all_read[cur_page] = (sumIOLength < sumLength) ? 1 : 0;

			cur_page++;
			continue;
		}

		// 处理最后一页
		if(cur_page == num_pages - 1){
			// 如果最后一页不满则全读，注意是到 end_pos 结束
			int sumLength = (end_pos % Aligned_Size == 0 ) ? Aligned_Size : (end_pos % Aligned_Size); // 最后一页的 IO 请求总长度
			int sumIOLength = 0; // 最后一页的 bladeIO 请求的总长度
			for(int k = 0;k < num_blade_io;k++){
				if(blade_io[k].userpageid == cur_page){
					sumIOLength += blade_io[k].count;
				}
			}
			// 不会出现 bladeIO 终点大于 end_pos 的情况,前面代码已经保证了
			is_page_all_read[cur_page] = (sumIOLength < sumLength) ? 1 : 0;

			cur_page++;
			continue;
		}


		// 处理中间页每 320K
		if(cur_page + block_page_num - 1 < num_pages - 1){ // 判断是否还有 320K
			int sumIOLength = 0; // 当前 320K 的 bladeIO 请求的总长度
			// 计算当前 320K 的 bladeIO 请求的总长度
			for(int j = cur_page;j <= cur_page + block_page_num - 1;j++){
				for(int k = 0;k < num_blade_io;k++){
					if(blade_io[k].userpageid == j){
						sumIOLength += blade_io[k].count;
					}
				}
			}
			if(sumIOLength < read_all_percent * block_page_size){ // bladeIO 占比不到 40%,则全读
				for(int j = cur_page;j <= cur_page + block_page_num - 1;j++){
					is_page_all_read[j] = 1;
				}
			}
			else { // bladeIO 占比比较大，则遍历每一页，如果当前页不是满的，则全读
				for(int j = cur_page;j <= cur_page + block_page_num - 1;j++){
					int sumIOLength = 0; // 当前页的 bladeIO 请求的总长度
					for(int k = 0;k < num_blade_io;k++){
						if(blade_io[k].userpageid == j){
							sumIOLength += blade_io[k].count;
						}
					}
					if(sumIOLength != Aligned_Size){
						is_page_all_read[j] = 1;
					}
				}
			}
			cur_page += block_page_num;
		}
		else { // 中间页不够 320K，则直接遍历每一页，如果当前页不是满的，则全读
			for(int j = cur_page;j < num_pages - 1;j++){
				int sumIOLength = 0; // 当前页的 bladeIO 请求的总长度
				for(int k = 0;k < num_blade_io;k++){
					if(blade_io[k].userpageid == j){
						sumIOLength += blade_io[k].count;
					}
				}
				if(sumIOLength != Aligned_Size){
					is_page_all_read[j] = 1;
				}
			}
			cur_page = num_pages - 1;
		}
	}
	cur_page = 0;
	printk("----------------------------");
	for(int k = 0;k < num_pages;k++){
		if(is_page_all_read[k] == 1){
			printk("[BUFFERED READ INFO]: page %d is all read.\n",k);
		}
		else {
			printk("[BUFFERED READ INFO]: page %d is not all read.\n",k);
		}
	}
	printk("----------------------------");
	// 处理每一页的读请求，读取每一段连续的读请求
	while(cur_page < num_pages){
		printk("[BUFFERED READ INFO]: In buffered read. cur_page = %d num_pages = %d\n",cur_page,num_pages);
		// 找到从当前页开始的最大连续的全读页
		int end_page = cur_page;
		while(end_page < num_pages && is_page_all_read[end_page] == 1){
			end_page++;
		}
		if(end_page >= num_pages) end_page = num_pages - 1; // 防止越界

		// 一次性读取从 cur_page 到 end_page 的所有页
		iocb->ki_pos = start_pos + cur_page * Aligned_Size;
		if(cur_page != 0) iocb->ki_pos -= start_pos % Aligned_Size; // 不是第一页，需要调整 ki_pos 到页的起始位置
		to->count = (end_page - cur_page + 1) * Aligned_Size;
		if(cur_page == 0) to->count -= start_pos % Aligned_Size; // 第一页需要减去头部不包含的部分
		if(end_page == num_pages - 1) to->count -= Aligned_Size - ( (end_pos % Aligned_Size == 0 ) ? Aligned_Size : (end_pos % Aligned_Size) ); // 最后一页需要减去尾部不包含的部分

		ssize_t buffered_read_ret = xfs_file_buffered_read(iocb, to);
		printk("[BUFFERED READ INFO]: buffered read ret = %ld\n",buffered_read_ret);

		cur_page = end_page + 1;			
	}
	printk("[BUFFERED READ INFO]: buffered read end. ------------------------------------");
#elif defined(NO_MAGNIFICATION_READ_STRATEGY)
	// 硬读策略，没有blade IO的就读，有的就不读，这种读策略不会出现读放大的问题，但是可能会频繁读取
	BLADE_PAGE_OFFSET cur_offset = iocb->ki_pos;
	BLADE_PAGE_OFFSET end_offset = iocb->ki_pos + to->count - 1;

	// printk("[READ ITER INFO]: ki_pos = %ld ki_endpos = %ld count = %ld\n",iocb->ki_pos,iocb->ki_pos + to->count - 1,to->count);

	while(cur_offset < end_offset){
		// printk("[BUFFERED READ INFO]: cur_offset = %ld end_offset = %ld\n",cur_offset,end_offset);
		BLADE_PAGE_OFFSET io_start_pos = cur_offset;
		BLADE_PAGE_OFFSET io_end_pos = end_offset;
		// printk("[BUFFERED READ INFO]: init cur_offset = %ld end_offset = %ld\n",io_start_pos,io_end_pos);
		// 标记当前的 IO 请求是否合法
		BOOL legal_io = TRUE;
		// 扫描所有的 blade IO 请求，不断调整 io_end_pos
		for(int k = 0;k < num_blade_io;k++){
			// 如果当前的 blade IO 请求和当前的 IO 请求有交集
			BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].userpageid * Aligned_Size + blade_io[k].pos;
			BLADE_PAGE_OFFSET cur_blade_io_end_offset = cur_blade_io_start_offset + blade_io[k].count - 1;
			if(io_start_pos <= cur_blade_io_end_offset && io_end_pos >= cur_blade_io_start_offset){
				// 调整 io_end_pos 为其与 cur_blade_io_start_offset - 1 的较小值
				io_end_pos = mymin(io_end_pos,cur_blade_io_start_offset - 1);
			}
			if(io_end_pos < io_start_pos){ // 当前的 IO 请求不合法
				legal_io = FALSE;
				break;
			}
			// printk("[BUFFERED READ INFO]: k = %d num_blade_io = %d cur_blade_io_pos = %ld cur_offset = %ld end_offset = %ld\n",k,num_blade_io,blade_io[k].pos,io_start_pos,io_end_pos);
		}

		// 如果当前的 IO 请求合法，则读取
		if(legal_io){
			iocb->ki_pos = io_start_pos;
			to->count = io_end_pos - io_start_pos + 1;
			// printk("[BUFFERED READ INFO]: --------- DO BUFFERED READ\n");
			// for(int k = 0;k < num_blade_io;k++){
			// 	BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].userpageid * Aligned_Size + blade_io[k].pos;
			// 	// BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].pageid * Aligned_Size + blade_io[k].pos;
			// 	BLADE_PAGE_OFFSET cur_blade_io_end_offset = cur_blade_io_start_offset + blade_io[k].count - 1;
			// 	// printk("[BUFFERED READ INFO]: k = %d num_blade_io = %d blade_io_start_pos = %ld blade_io_end_pos = %ld\n",k,num_blade_io,cur_blade_io_start_offset,cur_blade_io_end_offset);
			// 	// traverse_allpage_bladeIO(blade_io[k].pageid);
			// }
			// printk("[BUFFERED READ INFO]: io_start_pos = %ld io_end_pos = %ld to->count = %ld\n",io_start_pos,io_end_pos,to->count);
			sum_buffered_read_request_len += to->count;
			// ssize_t buffered_read_ret = 0;
			ssize_t buffered_read_ret = xfs_file_buffered_read(iocb, to);
			RET += buffered_read_ret;
			sum_buffered_read_success_len += buffered_read_ret;
			// 更新 cur_offset
			cur_offset = io_end_pos + 1;
		}
		else { // 当前请求不合法，说明当前位置有 blade IO，那么 offset 指针应当跳到所有后方 blade IO 的末尾的下一位置的最小值
			BLADE_PAGE_OFFSET min_next_pos = end_offset;
			for(int k = 0;k < num_blade_io;k++){
				BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].userpageid * Aligned_Size + blade_io[k].pos;
				// BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].pageid * Aligned_Size + blade_io[k].pos;
				BLADE_PAGE_OFFSET cur_blade_io_end_offset = cur_blade_io_start_offset + blade_io[k].count - 1;
				if(cur_blade_io_end_offset >= cur_offset){
					min_next_pos = mymin(min_next_pos,cur_blade_io_end_offset + 1);
				}
			}
			cur_offset = min_next_pos;
		}
	}	
	// // 硬读策略，没有blade IO的就读，有的就不读，这种读策略不会出现读放大的问题，但是可能会频繁读取
	// BLADE_PAGE_OFFSET cur_offset = iocb->ki_pos;
	// BLADE_PAGE_OFFSET end_offset = iocb->ki_pos + to->count - 1;
	// ssize_t tocount = to->count;
	// ssize_t kipos = iocb->ki_pos;

	// // printk("[READ ITER INFO]: ki_pos = %ld ki_endpos = %ld count = %ld\n",iocb->ki_pos,iocb->ki_pos + to->count - 1,to->count);

	// while(cur_offset < end_offset){
	// 	// printk("[BUFFERED READ INFO]: cur_offset = %ld end_offset = %ld\n",cur_offset,end_offset);
	// 	BLADE_PAGE_OFFSET io_start_pos = cur_offset;
	// 	BLADE_PAGE_OFFSET io_end_pos = end_offset;
	// 	// printk("[BUFFERED READ INFO]: init cur_offset = %ld end_offset = %ld\n",io_start_pos,io_end_pos);
	// 	// 标记当前的 IO 请求是否合法
	// 	BOOL legal_io = TRUE;
	// 	// 扫描所有的 blade IO 请求，不断调整 io_end_pos
	// 	for(int k = 0;k < num_blade_io;k++){
	// 		// 如果当前的 blade IO 请求和当前的 IO 请求有交集
	// 		// BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].userpageid * Aligned_Size + blade_io[k].pos;
	// 		BLADE_PAGE_OFFSET cur_blade_io_start_offset = kipos + mymax(0,( 1ll * Aligned_Size * blade_io[k].userpageid + blade_io[k].pos - kipos % Aligned_Size));
	// 		BLADE_PAGE_OFFSET cur_blade_io_end_offset = cur_blade_io_start_offset + blade_io[k].count - 1;
	// 		if(io_start_pos <= cur_blade_io_end_offset && io_end_pos >= cur_blade_io_start_offset){
	// 			// 调整 io_end_pos 为其与 cur_blade_io_start_offset - 1 的较小值
	// 			io_end_pos = mymin(io_end_pos,cur_blade_io_start_offset - 1);
	// 			// io_end_pos = mymin(io_end_pos,cur_blade_io_start_offset);
	// 		}
	// 		if(io_end_pos < io_start_pos){ // 当前的 IO 请求不合法
	// 			legal_io = FALSE;
	// 			break;
	// 		}
	// 		// printk("[BUFFERED READ INFO]: k = %d num_blade_io = %d cur_blade_io_pos = %ld cur_offset = %ld end_offset = %ld\n",k,num_blade_io,blade_io[k].pos,io_start_pos,io_end_pos);
	// 	}

	// 	// 如果当前的 IO 请求合法，则读取
	// 	if(legal_io){
	// 		iocb->ki_pos = io_start_pos;
	// 		// to->count = io_end_pos - io_start_pos + 1;
	// 		// to->count = 0;
	// 		// printk("[BUFFERED READ INFO]: --------- DO BUFFERED READ\n");
	// 		// for(int k = 0;k < num_blade_io;k++){
	// 		// 	BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].userpageid * Aligned_Size + blade_io[k].pos;
	// 		// 	// BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].pageid * Aligned_Size + blade_io[k].pos;
	// 		// 	BLADE_PAGE_OFFSET cur_blade_io_end_offset = cur_blade_io_start_offset + blade_io[k].count - 1;
	// 		// 	// printk("[BUFFERED READ INFO]: k = %d num_blade_io = %d blade_io_start_pos = %ld blade_io_end_pos = %ld\n",k,num_blade_io,cur_blade_io_start_offset,cur_blade_io_end_offset);
	// 		// 	// traverse_allpage_bladeIO(blade_io[k].pageid);
	// 		// }
	// 		// printk("[BUFFERED READ INFO]: io_start_pos = %ld io_end_pos = %ld to->count = %ld\n",io_start_pos,io_end_pos,to->count);
	// 		sum_buffered_read_request_len += to->count;
	// 		ssize_t buffered_read_ret = 0;

	// 		struct kvec kvec;
	// 		kvec.iov_base = no_maganification_read_buf;
	// 		kvec.iov_len = io_end_pos - io_start_pos + 1;
	// 		struct iov_iter new_iter;
	// 		iov_iter_kvec(&new_iter, READ, &kvec, 1, kvec.iov_len);

	// 		buffered_read_ret = xfs_file_buffered_read(iocb, &new_iter);
	// 		// copy_to_user((char *)(to->ubuf) + (io_start_pos - kipos), no_maganification_read_buf, io_end_pos - io_start_pos + 1);

	// 		RET += buffered_read_ret;
	// 		sum_buffered_read_success_len += buffered_read_ret;
	// 		buf_read_ret += buffered_read_ret;
	// 		// 更新 cur_offset
	// 		cur_offset = io_end_pos + 1;
	// 	}
	// 	else { // 当前请求不合法，说明当前位置有 blade IO，那么 offset 指针应当跳到所有后方 blade IO 的末尾的下一位置的最小值
	// 		BLADE_PAGE_OFFSET min_next_pos = end_offset;
	// 		for(int k = 0;k < num_blade_io;k++){
	// 			// BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].userpageid * Aligned_Size + blade_io[k].pos;
	// 			BLADE_PAGE_OFFSET cur_blade_io_start_offset = kipos + mymax(0,( 1ll * Aligned_Size * blade_io[k].userpageid + blade_io[k].pos - kipos % Aligned_Size));
	// 			// BLADE_PAGE_OFFSET cur_blade_io_start_offset = blade_io[k].pageid * Aligned_Size + blade_io[k].pos;
	// 			BLADE_PAGE_OFFSET cur_blade_io_end_offset = cur_blade_io_start_offset + blade_io[k].count - 1;
	// 			if(cur_blade_io_end_offset >= cur_offset){
	// 				min_next_pos = mymin(min_next_pos,cur_blade_io_end_offset + 1);
	// 			}
	// 		}
	// 		cur_offset = min_next_pos;
	// 		// cur_offset += 1;
	// 	}
	// }
#elif defined(BASIC_READ_STRATEGY)
	// ssize_t buffered_read_ret = xfs_file_buffered_read(iocb, to);
	RET = xfs_file_buffered_read(iocb, to);
#else
	// 旧版本：一页一页处理
	int now_blade_io_id = 0;
	int sum_toubuf_offset = 0;
	for(int i=0;i<num_pages;i++)
	{
		int unaligned_blade_io = 0;
		int page_blade_iosize = 0;
		while(now_blade_io_id<num_blade_io)
		{	// 如果当前blade io不足一个Aligned_Size， buffered io读整个Aligned_Size
			if(blade_io[now_blade_io_id].userpageid == i) // 当前页是否有与 blade_io 命中的部分
			{
				if(blade_io[now_blade_io_id].count != Aligned_Size)//头尾分别处理一下
					unaligned_blade_io++;
				page_blade_iosize += blade_io[now_blade_io_id].count;
				now_blade_io_id++; 
			}
			else break;
		}
		if(unaligned_blade_io || page_blade_iosize == 0)
		{
			// iocb->ki_pos = start_pos + add;
			// iocb->ki_len = blade_io[nowbladeio].userpageid*Aligned_Size+blade_io[nowbladeio].pos - (pos+add);
			// iocb->ubuf = (char*)userbuf + add;
			// loff_t page_start =start_pos + i * Aligned_Size; // 当前页的全局起始位置
			// loff_t page_end = page_start + Aligned_Size;
			// printk("enter buffer read i == %d\n",i);

			
			if (i == 0) 
			{ 
				iocb->ki_pos = start_pos;
				to->count = Aligned_Size - start_pos%Aligned_Size;
				// to->ubuf = (char *)userbuf; 
				// printk("to->count = %ld\n",to->count);
				// printk("come into buffered read(i=0)!!\n");
				// printk("iter->count = %ld\n",iter.count);

				sum_toubuf_offset += to->count;
				// atomic_inc(&SSD_task_num[0]); 
				ret += xfs_file_buffered_read(iocb, to);
				// atomic_dec(&SSD_task_num[0]); 
				// printk("i == 0 buffer read ret = %d\n",ret);
			

				// printk("ret (i=0) = %d\n",ret);
			} 
			else if (i == num_pages - 1) { 
				// 结束页处理

				iocb->ki_pos =  start_pos + i * Aligned_Size - start_pos%Aligned_Size; //-1 +1
				to->count = end_pos - iocb->ki_pos;
				// printk("pre 1 to->ubuf address = %p\n",to->ubuf);
				// to->ubuf = (char __user *)to->ubuf + i * Aligned_Size - start_pos%Aligned_Size;
				// printk("pre 2 to->ubuf address = %p\n",to->ubuf);

				// printk("to->count = %ld\n",to->count);
				// printk("come into buffered read(i=0)!!\n");
				// printk("iter->count = %ld\n",iter.count);

				sum_toubuf_offset += to->count;
				ret += xfs_file_buffered_read(iocb, to);
				// printk("i == numpages - 1 buffer read ret = %d\n",ret);

				// printk("ret (i = finalpage) = %ld",ret);
				// printk("aft 1 to->ubuf address = %p\n",to->ubuf);
				// to->ubuf = (char __user *)to->ubuf + start_pos%Aligned_Size - i * Aligned_Size;
				// printk("aft 2 to->ubuf address = %p\n",to->ubuf);
			} else { 
				// 中间页处理
				iocb->ki_pos =  start_pos + i * Aligned_Size - start_pos%Aligned_Size; //-1 +1
				to->count = Aligned_Size;
				// to->ubuf = (char __user *)to->ubuf + i * Aligned_Size - start_pos%Aligned_Size;
				
				// printk("to->count = %ld\n",to->count);
				// printk("come into buffered read(i=0)!!\n");
				// printk("iter->count = %ld\n",iter.count);

				sum_toubuf_offset += to->count;
				// printk("pre bufread to offset = %p",to->ubuf);
				ret += xfs_file_buffered_read(iocb, to);
				// printk("aft bufread to offset = %p",to->ubuf);
				// printk("i == mid pages buffer read ret = %d offset = %d ki_pos = %ld\n",ret,-start_pos%Aligned_Size + i * Aligned_Size,iocb->ki_pos);

				// printk("ret (i = pages) = %ld",ret);
				// to->ubuf = (char __user *)to->ubuf + start_pos%Aligned_Size - i * Aligned_Size;
				
			}
		}
	}
#endif

	// 	}
		// else 
		// {
		// 	int nowbladeio=0;
		// 	pos = start_pos%Aligned_Size;
		// 	size_t add =0;
		// 	void * userbuf = iocb->ubuf;
		// 	while(add<count)
		// 	{
		// 		if(pos+add<blade_io[nowbladeio].userpageid*Aligned_Size+blade_io[nowbladeio].pos)
		// 		{
		// 			iocb->ki_pos = start_pos + add;
		// 			iocb->ki_len = blade_io[nowbladeio].userpageid*Aligned_Size+blade_io[nowbladeio].pos - (pos+add);
		// 			iocb->ubuf = (char*)userbuf + add;
		// 			add += iocb->ki_len;
		// 			ret += xfs_file_buffered_read(iocb, to);
		// 			nowbladeio ++;
		// 		}
		// 		else if(pos+add == blade_io[nowbladeio].userpageid*Aligned_Size+blade_io[nowbladeio].pos)
		// 		{
		// 			add += blade_io[nowbladeio].len;
		// 			nowbladeio ++;
		// 		}
		// 		if(nowbladeio==num_blade_io)
		// 		{
		// 			if(add<count)
		// 			{
		// 				iocb->ki_pos = start_pos + add;
		// 				iocb->ki_len = count - add;
		// 				iocb->ubuf = (char*)userbuf + add;
		// 				ret += xfs_file_buffered_read(iocb, to);
		// 				break;
		// 			}
		// 		}
		// 	}
		// }
	// }
	// printk("after for to->ubuf address = %p\n",to->ubuf);

	// to->ubuf = (char *)userbuf;
	//to->ubuf = (char __user *)to->ubuf - sum_toubuf_offset;
	// printk("sum_toubuf_offset = %d\n",sum_toubuf_offset);
	// printk("char __user = %d",sizeof(char __user));
	// char *tempbuf = vmalloc(8192);
	// for(int i = 0;i < 8192;i++) tempbuf[i] = 0;

	// copy_to_user(to->ubuf, (char *)tempbuf, 8192);

	// vfree(tempbuf);
	// tempbuf = NULL;

	for(int i=0;i<num_blade_io;i++)
	// for(int i=0;i<1;i++)
	{
		// ret += copy_to_user((to->ubuf), (char *)(allpage_data) + 1ll * blade_io[i].pageid * Aligned_Size + blade_io[i].pos,to->count);
		// break;

		// if(i != 1) continue;
		// printk("***********pre ret = %ld count = %ld i = %d num_blade_io = %d add1 = %lld add2 = %lld add3 = %lld add4 = %lld\n",ret, blade_io[i].count,i,num_blade_io,1ll*blade_io[i].userpageid , 1ll *blade_io[i].pos,1ll * Aligned_Size*blade_io[i].userpageid + blade_io[i].pos , start_pos % Aligned_Size);
		// ret += copy_to_user((char __user *)(to->ubuf)+1ll * Aligned_Size*blade_io[i].userpageid+blade_io[i].pos - start_pos%Aligned_Size, (char *)(memorycache)+(Aligned_Size+Page_Meta_Size)*blade_io[i].pageid+Page_Meta_Size+blade_io[i].pos,blade_io[i].count); 
		// to->ubuf = (char __user *)(to->ubuf) + 1;
		// to->ubuf = (char __user *)(to->ubuf) + 1ll * Aligned_Size*blade_io[i].userpageid + blade_io[i].pos;
		to->ubuf = (char __user *)(to->ubuf) + mymax(0,( 1ll * Aligned_Size*blade_io[i].userpageid + blade_io[i].pos - start_pos%Aligned_Size));
		// to->ubuf = (char __user*)(to->ubuf) + 16725;
		// printk("i = %d memorycache_offset = %d bladeio_pos = %d\n",i,(Aligned_Size+Page_Meta_Size)*blade_io[i].pageid+Page_Meta_Size+blade_io[i].pos,blade_io[i].pos);
		// if (!access_ok(to->ubuf, blade_io[i].count)) {
		// 	printk(KERN_ERR "Invalid user space address after applying offset\n");
		// }
		// ret += copy_to_user((void __user *)((char __user *)(to->ubuf)+1ll * Aligned_Size*blade_io[i].userpageid+blade_io[i].pos - start_pos%Aligned_Size), (char *)(memorycache)+(Aligned_Size+Page_Meta_Size)*blade_io[i].pageid+Page_Meta_Size+blade_io[i].pos,blade_io[i].count); 
		// printk("pre copytouser tobuf offset = %p",to->ubuf);

		if(blade_io[i].pos < 0 || blade_io[i].pos >= Aligned_Size || blade_io[i].count < 0 || blade_io[i].count > Aligned_Size){
			printk("[COPY TO USER]: ERROR POS. blade_io[%d].pos = %d blade_io[%d].count = %d\n",i,blade_io[i].pos,i,blade_io[i].count);
		}
		// else ret += copy_to_user((to->ubuf), (char *)(memorycache)+(Aligned_Size+Page_Meta_Size)*blade_io[i].pageid+Page_Meta_Size+blade_io[i].pos,blade_io[i].count); 
		else {
			ret += copy_to_user((to->ubuf), (char *)(allpage_data) + 1ll * blade_io[i].pageid * Aligned_Size + blade_io[i].pos,blade_io[i].count);
			// printk("[COPY TO USER]: copy count = %ld", blade_io[i].count);
			// ssize_t cur_user_start_pos = initial_ki_pos + mymax(0,( 1ll * Aligned_Size*blade_io[i].userpageid + blade_io[i].pos - start_pos%Aligned_Size));
			// ssize_t user_end_pos = initial_ki_pos + initial_to_count - 1;
			// ssize_t copy_to_user_ret = copy_to_user((to->ubuf), (char *)(allpage_data) + 1ll * blade_io[i].pageid * Aligned_Size + blade_io[i].pos, mymin(blade_io[i].count, user_end_pos - cur_user_start_pos + 1));
			// RET += mymin(blade_io[i].count, user_end_pos - cur_user_start_pos + 1)  - copy_to_user_ret;
			// blade_read_ret += mymin(blade_io[i].count, user_end_pos - cur_user_start_pos + 1)  - copy_to_user_ret;
		}


		// printk("aft copytouser tobuf offset = %p",to->ubuf);
		// for(int i = 0;i < mymin(10,blade_io[i].count);i++){
		// 	printk("%c",((char *)(memorycache)+(Aligned_Size+Page_Meta_Size)*blade_io[i].pageid+Page_Meta_Size+blade_io[i].pos)[i]);
		// }

		// to->ubuf = (char __user *)(to->ubuf) - blade_io[i].count;
		to->ubuf = (char __user *)(to->ubuf) - mymax(0,( 1ll * Aligned_Size*blade_io[i].userpageid + blade_io[i].pos - start_pos%Aligned_Size));
		// to->ubuf = (char __user *)(to->ubuf) - ( 1ll * Aligned_Size*blade_io[i].userpageid + blade_io[i].pos - start_pos%Aligned_Size);

		// to->ubuf = (char __user *)(to->ubuf) - ( 1ll * Aligned_Size*blade_io[i].userpageid + blade_io[i].pos + (Aligned_Size - start_pos%Aligned_Size) % Aligned_Size );
		// to->ubuf = (char __user *)(to->ubuf) - 1ll * Aligned_Size*blade_io[i].userpageid - blade_io[i].pos - (Aligned_Size - start_pos%Aligned_Size) % Aligned_Size;
		// to->ubuf = (char __user *)(to->ubuf) - 1ll * Aligned_Size*blade_io[i].userpageid - blade_io[i].pos;

		// printk("***********aft ret = %ld count = %ld i = %d num_blade_io = %d\n",ret, blade_io[i].count,i,num_blade_io);
		// break;
	}

	// if(num_blade_io == 0){
	// 	char *tempbuf = vmalloc(1);
	// 	tempbuf[0] = '\n';
	// 	copy_to_user((to->ubuf), (char *)tempbuf,1);
	// 	vfree(tempbuf);
	// 	tempbuf = NULL;
	// }

	// if (ret > 0)
		// XFS_STATS_ADD(mp, xs_read_bytes, ret);
io_done:
#ifdef NEW_BUFFERED_READ_STRATEGY
	vfree(is_page_all_read);
	is_page_all_read = NULL;
#endif
	// printk("OVER! return ret = %ld\n",ret);
    // return  ret;

#ifdef STATIC_RANGE_QUERY_RESULT

#ifdef USING_LOCK
	spin_lock(&static_range_query_result_lock);
#endif
	static_range_query_result_used[goat_range_query_result_idx] = FALSE;
#ifdef USING_LOCK
	spin_unlock(&static_range_query_result_lock);
#endif

#endif

#ifdef STATIC_BLADE_IO

#ifdef USING_LOCK
	spin_lock(&static_blade_io_lock);
#endif
	static_blade_io_used[goat_blade_io_idx] = FALSE;
#ifdef USING_LOCK
	spin_unlock(&static_blade_io_lock);
#endif

#endif

	// return ret;
	return RET;

bio_only:
	if (iocb->ki_flags & IOCB_DIRECT){
		ret = xfs_file_dio_read(iocb, to);
		// printk("ret dio read = %ld\n",ret);
	}
	else{
		ret = xfs_file_buffered_read(iocb, to);
		// printk("ret buffered io read = %ld\n",ret);
	}
	if (ret > 0)
		XFS_STATS_ADD(mp, xs_read_bytes, ret);
#ifdef NEW_BUFFERED_READ_STRATEGY
	vfree(is_page_all_read);
	is_page_all_read = NULL;
#endif

#ifdef STATIC_RANGE_QUERY_RESULT

#ifdef USING_LOCK
	spin_lock(&static_range_query_result_lock);
#endif
	static_range_query_result_used[goat_range_query_result_idx] = FALSE;
#ifdef USING_LOCK
	spin_unlock(&static_range_query_result_lock);
#endif

#endif

#ifdef STATIC_BLADE_IO

#ifdef USING_LOCK
	spin_lock(&static_blade_io_lock);
#endif
	static_blade_io_used[goat_blade_io_idx] = FALSE;
#ifdef USING_LOCK
	spin_unlock(&static_blade_io_lock);
#endif

#endif

	return ret;
	// return RET;
#endif



	if (IS_DAX(inode))
		ret = xfs_file_dax_read(iocb, to);
	else if (iocb->ki_flags & IOCB_DIRECT)
		ret = xfs_file_dio_read(iocb, to);
	else
		ret = xfs_file_buffered_read(iocb, to);

	if (ret > 0)
		XFS_STATS_ADD(mp, xs_read_bytes, ret);
	return ret;
}
#else
STATIC ssize_t
xfs_file_read_iter(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct inode		*inode = file_inode(iocb->ki_filp);
	struct xfs_mount	*mp = XFS_I(inode)->i_mount;
	ssize_t			ret = 0;

#ifdef XFS_PRINTK
	printk("read /mnt/xfstest/%ld %ld %ld\n", XFS_I(inode)->i_ino, iocb->ki_pos, to->count);
#endif

	XFS_STATS_INC(mp, xs_read_calls);

	if (xfs_is_shutdown(mp))
		return -EIO;

	if (IS_DAX(inode))
		ret = xfs_file_dax_read(iocb, to);
	else if (iocb->ki_flags & IOCB_DIRECT)
		ret = xfs_file_dio_read(iocb, to);
	else
		ret = xfs_file_buffered_read(iocb, to);

	if (ret > 0)
		XFS_STATS_ADD(mp, xs_read_bytes, ret);
	return ret;
}
#endif



STATIC ssize_t
xfs_file_splice_read(  //数据直接在文件描述符之间传输，允许将数据直接从文件传输到管道中，而不需要通过用户空间的复制。
	struct file		*in,
	loff_t			*ppos,
	struct pipe_inode_info	*pipe,
	size_t			len,
	unsigned int		flags)
{
	struct inode		*inode = file_inode(in);
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	ssize_t			ret = 0;

	XFS_STATS_INC(mp, xs_read_calls);

	if (xfs_is_shutdown(mp))
		return -EIO;

	trace_xfs_file_splice_read(ip, *ppos, len);

	xfs_ilock(ip, XFS_IOLOCK_SHARED);
	ret = filemap_splice_read(in, ppos, pipe, len, flags);
	xfs_iunlock(ip, XFS_IOLOCK_SHARED);
	if (ret > 0)
		XFS_STATS_ADD(mp, xs_read_bytes, ret);
	return ret;
}

/*
 * Common pre-write limit and setup checks.
 *
 * Called with the iolocked held either shared and exclusive according to
 * @iolock, and returns with it held.  Might upgrade the iolock to exclusive
 * if called for a direct write beyond i_size.
 */
STATIC ssize_t
xfs_file_write_checks(
	struct kiocb		*iocb,
	struct iov_iter		*from,
	unsigned int		*iolock)
{
	struct file		*file = iocb->ki_filp;
	struct inode		*inode = file->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			error = 0;
	size_t			count = iov_iter_count(from);
	bool			drained_dio = false;
	loff_t			isize;

restart:
	error = generic_write_checks(iocb, from);
	if (error <= 0)
		return error;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		error = break_layout(inode, false);
		if (error == -EWOULDBLOCK)
			error = -EAGAIN;
	} else {
		error = xfs_break_layouts(inode, iolock, BREAK_WRITE);
	}

	if (error)
		return error;

	/*
	 * For changing security info in file_remove_privs() we need i_rwsem
	 * exclusively.
	 */
	if (*iolock == XFS_IOLOCK_SHARED && !IS_NOSEC(inode)) {
		xfs_iunlock(ip, *iolock);
		*iolock = XFS_IOLOCK_EXCL;
		error = xfs_ilock_iocb(iocb, *iolock);
		if (error) {
			*iolock = 0;
			return error;
		}
		goto restart;
	}

	/*
	 * If the offset is beyond the size of the file, we need to zero any
	 * blocks that fall between the existing EOF and the start of this
	 * write.  If zeroing is needed and we are currently holding the iolock
	 * shared, we need to update it to exclusive which implies having to
	 * redo all checks before.
	 *
	 * We need to serialise against EOF updates that occur in IO completions
	 * here. We want to make sure that nobody is changing the size while we
	 * do this check until we have placed an IO barrier (i.e.  hold the
	 * XFS_IOLOCK_EXCL) that prevents new IO from being dispatched.  The
	 * spinlock effectively forms a memory barrier once we have the
	 * XFS_IOLOCK_EXCL so we are guaranteed to see the latest EOF value and
	 * hence be able to correctly determine if we need to run zeroing.
	 *
	 * We can do an unlocked check here safely as IO completion can only
	 * extend EOF. Truncate is locked out at this point, so the EOF can
	 * not move backwards, only forwards. Hence we only need to take the
	 * slow path and spin locks when we are at or beyond the current EOF.
	 */
	if (iocb->ki_pos <= i_size_read(inode))
		goto out;

	spin_lock(&ip->i_flags_lock);
	isize = i_size_read(inode);
	if (iocb->ki_pos > isize) {
		spin_unlock(&ip->i_flags_lock);

		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;

		if (!drained_dio) {
			if (*iolock == XFS_IOLOCK_SHARED) {
				xfs_iunlock(ip, *iolock);
				*iolock = XFS_IOLOCK_EXCL;
				xfs_ilock(ip, *iolock);
				iov_iter_reexpand(from, count);
			}
			/*
			 * We now have an IO submission barrier in place, but
			 * AIO can do EOF updates during IO completion and hence
			 * we now need to wait for all of them to drain. Non-AIO
			 * DIO will have drained before we are given the
			 * XFS_IOLOCK_EXCL, and so for most cases this wait is a
			 * no-op.
			 */
			inode_dio_wait(inode);
			drained_dio = true;
			goto restart;
		}

		trace_xfs_zero_eof(ip, isize, iocb->ki_pos - isize);
		error = xfs_zero_range(ip, isize, iocb->ki_pos - isize, NULL);
		if (error)
			return error;
	} else
		spin_unlock(&ip->i_flags_lock);

out:
	return kiocb_modified(iocb);
}

static int
xfs_dio_write_end_io(
	struct kiocb		*iocb,
	ssize_t			size,
	int			error,
	unsigned		flags)
{
	struct inode		*inode = file_inode(iocb->ki_filp);
	struct xfs_inode	*ip = XFS_I(inode);
	loff_t			offset = iocb->ki_pos;
	unsigned int		nofs_flag;

	trace_xfs_end_io_direct_write(ip, offset, size);

	if (xfs_is_shutdown(ip->i_mount))
		return -EIO;

	if (error)
		return error;
	if (!size)
		return 0;

	/*
	 * Capture amount written on completion as we can't reliably account
	 * for it on submission.
	 */
	XFS_STATS_ADD(ip->i_mount, xs_write_bytes, size);

	/*
	 * We can allocate memory here while doing writeback on behalf of
	 * memory reclaim.  To avoid memory allocation deadlocks set the
	 * task-wide nofs context for the following operations.
	 */
	nofs_flag = memalloc_nofs_save();

	if (flags & IOMAP_DIO_COW) {
		error = xfs_reflink_end_cow(ip, offset, size);
		if (error)
			goto out;
	}

	/*
	 * Unwritten conversion updates the in-core isize after extent
	 * conversion but before updating the on-disk size. Updating isize any
	 * earlier allows a racing dio read to find unwritten extents before
	 * they are converted.
	 */
	if (flags & IOMAP_DIO_UNWRITTEN) {
		error = xfs_iomap_write_unwritten(ip, offset, size, true);
		goto out;
	}

	/*
	 * We need to update the in-core inode size here so that we don't end up
	 * with the on-disk inode size being outside the in-core inode size. We
	 * have no other method of updating EOF for AIO, so always do it here
	 * if necessary.
	 *
	 * We need to lock the test/set EOF update as we can be racing with
	 * other IO completions here to update the EOF. Failing to serialise
	 * here can result in EOF moving backwards and Bad Things Happen when
	 * that occurs.
	 *
	 * As IO completion only ever extends EOF, we can do an unlocked check
	 * here to avoid taking the spinlock. If we land within the current EOF,
	 * then we do not need to do an extending update at all, and we don't
	 * need to take the lock to check this. If we race with an update moving
	 * EOF, then we'll either still be beyond EOF and need to take the lock,
	 * or we'll be within EOF and we don't need to take it at all.
	 */
	if (offset + size <= i_size_read(inode))
		goto out;

	spin_lock(&ip->i_flags_lock);
	if (offset + size > i_size_read(inode)) {
		i_size_write(inode, offset + size);
		spin_unlock(&ip->i_flags_lock);
		error = xfs_setfilesize(ip, offset, size);
	} else {
		spin_unlock(&ip->i_flags_lock);
	}

out:
	memalloc_nofs_restore(nofs_flag);
	return error;
}

static const struct iomap_dio_ops xfs_dio_write_ops = {
	.end_io		= xfs_dio_write_end_io,
};

/*
 * Handle block aligned direct I/O writes
 */
static noinline ssize_t
xfs_file_dio_write_aligned(
	struct xfs_inode	*ip,
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	unsigned int		iolock = XFS_IOLOCK_SHARED; //初始设置为共享锁
	ssize_t			ret;

	ret = xfs_ilock_iocb_for_write(iocb, &iolock);//尝试获取写入锁
	if (ret) //写入检查
		return ret;
	ret = xfs_file_write_checks(iocb, from, &iolock);// a
	if (ret)
		goto out_unlock;

	/*
	 * We don't need to hold the IOLOCK exclusively across the IO, so demote
	 * the iolock back to shared if we had to take the exclusive lock in
	 * xfs_file_write_checks() for other reasons.
	 */
	if (iolock == XFS_IOLOCK_EXCL) {//如果在xfs_file_wirte_checks中获取了独占锁 此时可以降级为共享锁，以便其他操作可以并发进行
		xfs_ilock_demote(ip, XFS_IOLOCK_EXCL);
		iolock = XFS_IOLOCK_SHARED;
	}
	//执行直接io写入
	trace_xfs_file_direct_write(iocb, from);
	ret = iomap_dio_rw(iocb, from, &xfs_direct_write_iomap_ops,
			   &xfs_dio_write_ops, 0, NULL, 0);
out_unlock:
	if (iolock)
		xfs_iunlock(ip, iolock);
	return ret;
}

/*
 * Handle block unaligned direct I/O writes
 *
 * In most cases direct I/O writes will be done holding IOLOCK_SHARED, allowing
 * them to be done in parallel with reads and other direct I/O writes.  However,
 * if the I/O is not aligned to filesystem blocks, the direct I/O layer may need
 * to do sub-block zeroing and that requires serialisation against other direct
 * I/O to the same block.  In this case we need to serialise the submission of
 * the unaligned I/O so that we don't get racing block zeroing in the dio layer.
 * In the case where sub-block zeroing is not required, we can do concurrent
 * sub-block dios to the same block successfully.
 *
 * Optimistically submit the I/O using the shared lock first, but use the
 * IOMAP_DIO_OVERWRITE_ONLY flag to tell the lower layers to return -EAGAIN
 * if block allocation or partial block zeroing would be required.  In that case
 * we try again with the exclusive lock.
 */
static noinline ssize_t
xfs_file_dio_write_unaligned(
	struct xfs_inode	*ip,
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	size_t			isize = i_size_read(VFS_I(ip));
	size_t			count = iov_iter_count(from);
	unsigned int		iolock = XFS_IOLOCK_SHARED; //设置共享锁，处理并发文件操作
	unsigned int		flags = IOMAP_DIO_OVERWRITE_ONLY; //初始值代表仅允许覆盖现有数据的直接写入
	ssize_t			ret;

	/*
	 * Extending writes need exclusivity because of the sub-block zeroing
	 * that the DIO code always does for partial tail blocks beyond EOF, so
	 * don't even bother trying the fast path in this case.
	 */
	if (iocb->ki_pos > isize || iocb->ki_pos + count >= isize) { //处理扩展写入 即超出文件大小的写入
		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;
retry_exclusive:
		iolock = XFS_IOLOCK_EXCL;
		flags = IOMAP_DIO_FORCE_WAIT;
	}

	ret = xfs_ilock_iocb_for_write(iocb, &iolock); //锁定io进行写入操作
	if (ret)
		return ret;

	/*
	 * We can't properly handle unaligned direct I/O to reflink files yet,
	 * as we can't unshare a partial block.
	 */
	if (xfs_is_cow_inode(ip)) { 
		trace_xfs_reflink_bounce_dio_write(iocb, from);
		ret = -ENOTBLK;
		goto out_unlock;
	}

	ret = xfs_file_write_checks(iocb, from, &iolock);
	if (ret)
		goto out_unlock;

	/*
	 * If we are doing exclusive unaligned I/O, this must be the only I/O
	 * in-flight.  Otherwise we risk data corruption due to unwritten extent
	 * conversions from the AIO end_io handler.  Wait for all other I/O to
	 * drain first.
	 */
	if (flags & IOMAP_DIO_FORCE_WAIT)// 等待未完成的io操作 表示写操作必须等待其他io操作完成
		inode_dio_wait(VFS_I(ip));

	trace_xfs_file_direct_write(iocb, from);
	ret = iomap_dio_rw(iocb, from, &xfs_direct_write_iomap_ops,
			   &xfs_dio_write_ops, flags, NULL, 0); //执行实际的io写入操作
	/* 两个操作数	
		xfs_direct_write_iomap_ops：是 XFS 在处理 直接写入操作 时的块映射回调函数集。
		它负责将文件的逻辑偏移量映射到具体的物理块，并在写入完成后更新元数据。

		xfs_dio_write_ops：是 XFS 在执行 直接 I/O 操作 时使用的 I/O 操作回调函数集。
		它负责管理数据的实际写入过程，确保数据通过直接 I/O 高效地传输到磁盘。

	*/

	/*
	 * Retry unaligned I/O with exclusive blocking semantics if the DIO
	 * layer rejected it for mapping or locking reasons. If we are doing
	 * nonblocking user I/O, propagate the error.
	 */
	if (ret == -EAGAIN && !(iocb->ki_flags & IOCB_NOWAIT)) {
		ASSERT(flags & IOMAP_DIO_OVERWRITE_ONLY);
		xfs_iunlock(ip, iolock);
		goto retry_exclusive;
	}

out_unlock:
	if (iolock)
		xfs_iunlock(ip, iolock);
	return ret;
}

ssize_t
xfs_file_dio_write(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));
	struct xfs_buftarg      *target = xfs_inode_buftarg(ip);
	size_t			count = iov_iter_count(from);

	/* direct I/O must be aligned to device logical sector size */
	if ((iocb->ki_pos | count) & target->bt_logical_sectormask)
		return -EINVAL;
	if ((iocb->ki_pos | count) & ip->i_mount->m_blockmask)
		return xfs_file_dio_write_unaligned(ip, iocb, from);
	return xfs_file_dio_write_aligned(ip, iocb, from);
}

static noinline ssize_t
xfs_file_dax_write(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	struct inode		*inode = iocb->ki_filp->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	unsigned int		iolock = XFS_IOLOCK_EXCL;
	ssize_t			ret, error = 0;
	loff_t			pos;

	
	ret = xfs_ilock_iocb(iocb, iolock);
	if (ret)
		return ret;
	ret = xfs_file_write_checks(iocb, from, &iolock);
	if (ret)
		goto out;

	pos = iocb->ki_pos;

	trace_xfs_file_dax_write(iocb, from);
	ret = dax_iomap_rw(iocb, from, &xfs_dax_write_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		error = xfs_setfilesize(ip, pos, ret);
	}
out:
	if (iolock)
		xfs_iunlock(ip, iolock);
	if (error)
		return error;

	if (ret > 0) {
		XFS_STATS_ADD(ip->i_mount, xs_write_bytes, ret);

		/* Handle various SYNC-type writes */
		ret = generic_write_sync(iocb, ret);
	}
	return ret;
}

STATIC ssize_t
xfs_file_buffered_write(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	struct inode		*inode = iocb->ki_filp->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;
	bool			cleared_space = false;
	unsigned int		iolock;

write_retry:
	iolock = XFS_IOLOCK_EXCL;
	ret = xfs_ilock_iocb(iocb, iolock);
	if (ret)
		return ret;

	ret = xfs_file_write_checks(iocb, from, &iolock);
	if (ret)
		goto out;

	trace_xfs_file_buffered_write(iocb, from);
	ret = iomap_file_buffered_write(iocb, from,
			&xfs_buffered_write_iomap_ops);

	/*
	 * If we hit a space limit, try to free up some lingering preallocated
	 * space before returning an error. In the case of ENOSPC, first try to
	 * write back all dirty inodes to free up some of the excess reserved
	 * metadata space. This reduces the chances that the eofblocks scan
	 * waits on dirty mappings. Since xfs_flush_inodes() is serialized, this
	 * also behaves as a filter to prevent too many eofblocks scans from
	 * running at the same time.  Use a synchronous scan to increase the
	 * effectiveness of the scan.
	 */
	if (ret == -EDQUOT && !cleared_space) {
		xfs_iunlock(ip, iolock);
		xfs_blockgc_free_quota(ip, XFS_ICWALK_FLAG_SYNC);
		cleared_space = true;
		goto write_retry;
	} else if (ret == -ENOSPC && !cleared_space) {
		struct xfs_icwalk	icw = {0};

		cleared_space = true;
		xfs_flush_inodes(ip->i_mount);

		xfs_iunlock(ip, iolock);
		icw.icw_flags = XFS_ICWALK_FLAG_SYNC;
		xfs_blockgc_free_space(ip->i_mount, &icw);
		goto write_retry;
	}

out:
	if (iolock)
		xfs_iunlock(ip, iolock);

	if (ret > 0) {
		XFS_STATS_ADD(ip->i_mount, xs_write_bytes, ret);
		/* Handle various SYNC-type writes */
		ret = generic_write_sync(iocb, ret);
	}
	return ret;
}


static void
xfs_wait_dax_page(
	struct inode		*inode)
{
	struct xfs_inode        *ip = XFS_I(inode);

	xfs_iunlock(ip, XFS_MMAPLOCK_EXCL);
	schedule();
	xfs_ilock(ip, XFS_MMAPLOCK_EXCL);
}

int
xfs_break_dax_layouts(
	struct inode		*inode,
	bool			*retry)
{
	struct page		*page;

	ASSERT(xfs_isilocked(XFS_I(inode), XFS_MMAPLOCK_EXCL));

	page = dax_layout_busy_page(inode->i_mapping);
	if (!page)
		return 0;

	*retry = true;
	return ___wait_var_event(&page->_refcount,
			atomic_read(&page->_refcount) == 1, TASK_INTERRUPTIBLE,
			0, 0, xfs_wait_dax_page(inode));
}

int
xfs_break_layouts(
	struct inode		*inode,
	uint			*iolock,
	enum layout_break_reason reason)
{
	bool			retry;
	int			error;

	ASSERT(xfs_isilocked(XFS_I(inode), XFS_IOLOCK_SHARED|XFS_IOLOCK_EXCL));

	do {
		retry = false;
		switch (reason) {
		case BREAK_UNMAP:
			error = xfs_break_dax_layouts(inode, &retry);
			if (error || retry)
				break;
			fallthrough;
		case BREAK_WRITE:
			error = xfs_break_leased_layouts(inode, iolock, &retry);
			break;
		default:
			WARN_ON_ONCE(1);
			error = -EINVAL;
		}
	} while (error == 0 && retry);

	return error;
}

/* Does this file, inode, or mount want synchronous writes? */
static inline bool xfs_file_sync_writes(struct file *filp)
{
	struct xfs_inode	*ip = XFS_I(file_inode(filp));

	if (xfs_has_wsync(ip->i_mount))
		return true;
	if (filp->f_flags & (__O_SYNC | O_DSYNC))
		return true;
	if (IS_SYNC(file_inode(filp)))
		return true;

	return false;
}

#define	XFS_FALLOC_FL_SUPPORTED						\
		(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |		\
		 FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |	\
		 FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE)

STATIC long
xfs_file_fallocate(
	struct file		*file,
	int			mode,
	loff_t			offset,
	loff_t			len)
{
	struct inode		*inode = file_inode(file);
	struct xfs_inode	*ip = XFS_I(inode);
	long			error;
	uint			iolock = XFS_IOLOCK_EXCL | XFS_MMAPLOCK_EXCL;
	loff_t			new_size = 0;
	bool			do_file_insert = false;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;
	if (mode & ~XFS_FALLOC_FL_SUPPORTED)
		return -EOPNOTSUPP;

	xfs_ilock(ip, iolock);
	error = xfs_break_layouts(inode, &iolock, BREAK_UNMAP);
	if (error)
		goto out_unlock;

	/*
	 * Must wait for all AIO to complete before we continue as AIO can
	 * change the file size on completion without holding any locks we
	 * currently hold. We must do this first because AIO can update both
	 * the on disk and in memory inode sizes, and the operations that follow
	 * require the in-memory size to be fully up-to-date.
	 */
	inode_dio_wait(inode);

	/*
	 * Now AIO and DIO has drained we flush and (if necessary) invalidate
	 * the cached range over the first operation we are about to run.
	 *
	 * We care about zero and collapse here because they both run a hole
	 * punch over the range first. Because that can zero data, and the range
	 * of invalidation for the shift operations is much larger, we still do
	 * the required flush for collapse in xfs_prepare_shift().
	 *
	 * Insert has the same range requirements as collapse, and we extend the
	 * file first which can zero data. Hence insert has the same
	 * flush/invalidate requirements as collapse and so they are both
	 * handled at the right time by xfs_prepare_shift().
	 */
	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE |
		    FALLOC_FL_COLLAPSE_RANGE)) {
		error = xfs_flush_unmap_range(ip, offset, len);
		if (error)
			goto out_unlock;
	}

	error = file_modified(file);
	if (error)
		goto out_unlock;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		error = xfs_free_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		if (!xfs_is_falloc_aligned(ip, offset, len)) {
			error = -EINVAL;
			goto out_unlock;
		}

		/*
		 * There is no need to overlap collapse range with EOF,
		 * in which case it is effectively a truncate operation
		 */
		if (offset + len >= i_size_read(inode)) {
			error = -EINVAL;
			goto out_unlock;
		}

		new_size = i_size_read(inode) - len;

		error = xfs_collapse_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	} else if (mode & FALLOC_FL_INSERT_RANGE) {
		loff_t		isize = i_size_read(inode);

		if (!xfs_is_falloc_aligned(ip, offset, len)) {
			error = -EINVAL;
			goto out_unlock;
		}

		/*
		 * New inode size must not exceed ->s_maxbytes, accounting for
		 * possible signed overflow.
		 */
		if (inode->i_sb->s_maxbytes - isize < len) {
			error = -EFBIG;
			goto out_unlock;
		}
		new_size = isize + len;

		/* Offset should be less than i_size */
		if (offset >= isize) {
			error = -EINVAL;
			goto out_unlock;
		}
		do_file_insert = true;
	} else {
		if (!(mode & FALLOC_FL_KEEP_SIZE) &&
		    offset + len > i_size_read(inode)) {
			new_size = offset + len;
			error = inode_newsize_ok(inode, new_size);
			if (error)
				goto out_unlock;
		}

		if (mode & FALLOC_FL_ZERO_RANGE) {
			/*
			 * Punch a hole and prealloc the range.  We use a hole
			 * punch rather than unwritten extent conversion for two
			 * reasons:
			 *
			 *   1.) Hole punch handles partial block zeroing for us.
			 *   2.) If prealloc returns ENOSPC, the file range is
			 *       still zero-valued by virtue of the hole punch.
			 */
			unsigned int blksize = i_blocksize(inode);

			trace_xfs_zero_file_space(ip);

			error = xfs_free_file_space(ip, offset, len);
			if (error)
				goto out_unlock;

			len = round_up(offset + len, blksize) -
			      round_down(offset, blksize);
			offset = round_down(offset, blksize);
		} else if (mode & FALLOC_FL_UNSHARE_RANGE) {
			error = xfs_reflink_unshare(ip, offset, len);
			if (error)
				goto out_unlock;
		} else {
			/*
			 * If always_cow mode we can't use preallocations and
			 * thus should not create them.
			 */
			if (xfs_is_always_cow_inode(ip)) {
				error = -EOPNOTSUPP;
				goto out_unlock;
			}
		}

		if (!xfs_is_always_cow_inode(ip)) {
			error = xfs_alloc_file_space(ip, offset, len);
			if (error)
				goto out_unlock;
		}
	}

	/* Change file size if needed */
	if (new_size) {
		struct iattr iattr;

		iattr.ia_valid = ATTR_SIZE;
		iattr.ia_size = new_size;
		error = xfs_vn_setattr_size(file_mnt_idmap(file),
					    file_dentry(file), &iattr);
		if (error)
			goto out_unlock;
	}

	/*
	 * Perform hole insertion now that the file size has been
	 * updated so that if we crash during the operation we don't
	 * leave shifted extents past EOF and hence losing access to
	 * the data that is contained within them.
	 */
	if (do_file_insert) {
		error = xfs_insert_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	}

	if (xfs_file_sync_writes(file))
		error = xfs_log_force_inode(ip);

out_unlock:
	xfs_iunlock(ip, iolock);
	return error;
}

STATIC int
xfs_file_fadvise(
	struct file	*file,
	loff_t		start,
	loff_t		end,
	int		advice)
{
	struct xfs_inode *ip = XFS_I(file_inode(file));
	int ret;
	int lockflags = 0;

	/*
	 * Operations creating pages in page cache need protection from hole
	 * punching and similar ops
	 */
	if (advice == POSIX_FADV_WILLNEED) {
		lockflags = XFS_IOLOCK_SHARED;
		xfs_ilock(ip, lockflags);
	}
	ret = generic_fadvise(file, start, end, advice);
	if (lockflags)
		xfs_iunlock(ip, lockflags);
	return ret;
}

STATIC loff_t
xfs_file_remap_range(
	struct file		*file_in,
	loff_t			pos_in,
	struct file		*file_out,
	loff_t			pos_out,
	loff_t			len,
	unsigned int		remap_flags)
{
	struct inode		*inode_in = file_inode(file_in);
	struct xfs_inode	*src = XFS_I(inode_in);
	struct inode		*inode_out = file_inode(file_out);
	struct xfs_inode	*dest = XFS_I(inode_out);
	struct xfs_mount	*mp = src->i_mount;
	loff_t			remapped = 0;
	xfs_extlen_t		cowextsize;
	int			ret;

	if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
		return -EINVAL;

	if (!xfs_has_reflink(mp))
		return -EOPNOTSUPP;

	if (xfs_is_shutdown(mp))
		return -EIO;

	/* Prepare and then clone file data. */
	ret = xfs_reflink_remap_prep(file_in, pos_in, file_out, pos_out,
			&len, remap_flags);
	if (ret || len == 0)
		return ret;

	trace_xfs_reflink_remap_range(src, pos_in, len, dest, pos_out);

	ret = xfs_reflink_remap_blocks(src, pos_in, dest, pos_out, len,
			&remapped);
	if (ret)
		goto out_unlock;

	/*
	 * Carry the cowextsize hint from src to dest if we're sharing the
	 * entire source file to the entire destination file, the source file
	 * has a cowextsize hint, and the destination file does not.
	 */
	cowextsize = 0;
	if (pos_in == 0 && len == i_size_read(inode_in) &&
	    (src->i_diflags2 & XFS_DIFLAG2_COWEXTSIZE) &&
	    pos_out == 0 && len >= i_size_read(inode_out) &&
	    !(dest->i_diflags2 & XFS_DIFLAG2_COWEXTSIZE))
		cowextsize = src->i_cowextsize;

	ret = xfs_reflink_update_dest(dest, pos_out + len, cowextsize,
			remap_flags);
	if (ret)
		goto out_unlock;

	if (xfs_file_sync_writes(file_in) || xfs_file_sync_writes(file_out))
		xfs_log_force_inode(dest);
out_unlock:
	xfs_iunlock2_remapping(src, dest);
	if (ret)
		trace_xfs_reflink_remap_range_error(dest, ret, _RET_IP_);
	return remapped > 0 ? remapped : ret;
}

STATIC int
xfs_file_open(
	struct inode	*inode,
	struct file	*file)
{
	if (xfs_is_shutdown(XFS_M(inode->i_sb)))
		return -EIO;
	file->f_mode |= FMODE_NOWAIT | FMODE_BUF_RASYNC | FMODE_BUF_WASYNC |
			FMODE_DIO_PARALLEL_WRITE | FMODE_CAN_ODIRECT;
#ifdef XFS_PRINTK
	printk("open /mnt/xfstest/%ld\n", XFS_I(inode)->i_ino);
#endif
	return generic_file_open(inode, file);
}

STATIC int
xfs_dir_open(
	struct inode	*inode,
	struct file	*file)
{
	struct xfs_inode *ip = XFS_I(inode);
	unsigned int	mode;
	int		error;

	error = xfs_file_open(inode, file);
	if (error)
		return error;

	/*
	 * If there are any blocks, read-ahead block 0 as we're almost
	 * certain to have the next operation be a read there.
	 */
	mode = xfs_ilock_data_map_shared(ip);
	if (ip->i_df.if_nextents > 0)
		error = xfs_dir3_data_readahead(ip, 0, 0);
	xfs_iunlock(ip, mode);
	return error;
}

STATIC int
xfs_file_release(
	struct inode	*inode,
	struct file	*filp)
{
#ifdef XFS_PRINTK
	printk("close /mnt/xfstest/%ld\n", XFS_I(inode)->i_ino);
#endif
	return xfs_release(XFS_I(inode));
}

STATIC int
xfs_file_readdir(
	struct file	*file,
	struct dir_context *ctx)
{
	struct inode	*inode = file_inode(file);
	xfs_inode_t	*ip = XFS_I(inode);
	size_t		bufsize;

	/*
	 * The Linux API doesn't pass down the total size of the buffer
	 * we read into down to the filesystem.  With the filldir concept
	 * it's not needed for correct information, but the XFS dir2 leaf
	 * code wants an estimate of the buffer size to calculate it's
	 * readahead window and size the buffers used for mapping to
	 * physical blocks.
	 *
	 * Try to give it an estimate that's good enough, maybe at some
	 * point we can change the ->readdir prototype to include the
	 * buffer size.  For now we use the current glibc buffer size.
	 */
	bufsize = (size_t)min_t(loff_t, XFS_READDIR_BUFSIZE, ip->i_disk_size);

	return xfs_readdir(NULL, ip, ctx, bufsize);
}

STATIC loff_t
xfs_file_llseek(
	struct file	*file,
	loff_t		offset,
	int		whence)
{
	struct inode		*inode = file->f_mapping->host;

	if (xfs_is_shutdown(XFS_I(inode)->i_mount))
		return -EIO;

	switch (whence) {
	default:
		return generic_file_llseek(file, offset, whence);
	case SEEK_HOLE:
		offset = iomap_seek_hole(inode, offset, &xfs_seek_iomap_ops);
		break;
	case SEEK_DATA:
		offset = iomap_seek_data(inode, offset, &xfs_seek_iomap_ops);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, inode->i_sb->s_maxbytes);
}

#ifdef CONFIG_FS_DAX
static inline vm_fault_t
xfs_dax_fault(
	struct vm_fault		*vmf,
	unsigned int		order,
	bool			write_fault,
	pfn_t			*pfn)
{
	return dax_iomap_fault(vmf, order, pfn, NULL,
			(write_fault && !vmf->cow_page) ?
				&xfs_dax_write_iomap_ops :
				&xfs_read_iomap_ops);
}
#else
static inline vm_fault_t
xfs_dax_fault(
	struct vm_fault		*vmf,
	unsigned int		order,
	bool			write_fault,
	pfn_t			*pfn)
{
	ASSERT(0);
	return VM_FAULT_SIGBUS;
}
#endif

/*
 * Locking for serialisation of IO during page faults. This results in a lock
 * ordering of:
 *
 * mmap_lock (MM)
 *   sb_start_pagefault(vfs, freeze)
 *     invalidate_lock (vfs/XFS_MMAPLOCK - truncate serialisation)
 *       page_lock (MM)
 *         i_lock (XFS - extent map serialisation)
 */
static vm_fault_t
__xfs_filemap_fault(
	struct vm_fault		*vmf,
	unsigned int		order,
	bool			write_fault)
{
	struct inode		*inode = file_inode(vmf->vma->vm_file);
	struct xfs_inode	*ip = XFS_I(inode);
	vm_fault_t		ret;
	unsigned int		lock_mode = 0;

	trace_xfs_filemap_fault(ip, order, write_fault);

	if (write_fault) {
		sb_start_pagefault(inode->i_sb);
		file_update_time(vmf->vma->vm_file);
	}

	if (IS_DAX(inode) || write_fault)
		lock_mode = xfs_ilock_for_write_fault(XFS_I(inode));

	if (IS_DAX(inode)) {
		pfn_t pfn;

		ret = xfs_dax_fault(vmf, order, write_fault, &pfn);
		if (ret & VM_FAULT_NEEDDSYNC)
			ret = dax_finish_sync_fault(vmf, order, pfn);
	} else if (write_fault) {
		ret = iomap_page_mkwrite(vmf, &xfs_page_mkwrite_iomap_ops);
	} else {
		ret = filemap_fault(vmf);
	}

	if (lock_mode)
		xfs_iunlock(XFS_I(inode), lock_mode);

	if (write_fault)
		sb_end_pagefault(inode->i_sb);
	return ret;
}

static inline bool
xfs_is_write_fault(
	struct vm_fault		*vmf)
{
	return (vmf->flags & FAULT_FLAG_WRITE) &&
	       (vmf->vma->vm_flags & VM_SHARED);
}

static vm_fault_t
xfs_filemap_fault(
	struct vm_fault		*vmf)
{
	/* DAX can shortcut the normal fault path on write faults! */
	return __xfs_filemap_fault(vmf, 0,
			IS_DAX(file_inode(vmf->vma->vm_file)) &&
			xfs_is_write_fault(vmf));
}

static vm_fault_t
xfs_filemap_huge_fault(
	struct vm_fault		*vmf,
	unsigned int		order)
{
	if (!IS_DAX(file_inode(vmf->vma->vm_file)))
		return VM_FAULT_FALLBACK;

	/* DAX can shortcut the normal fault path on write faults! */
	return __xfs_filemap_fault(vmf, order,
			xfs_is_write_fault(vmf));
}

static vm_fault_t
xfs_filemap_page_mkwrite(
	struct vm_fault		*vmf)
{
	return __xfs_filemap_fault(vmf, 0, true);
}

/*
 * pfn_mkwrite was originally intended to ensure we capture time stamp updates
 * on write faults. In reality, it needs to serialise against truncate and
 * prepare memory for writing so handle is as standard write fault.
 */
static vm_fault_t
xfs_filemap_pfn_mkwrite(
	struct vm_fault		*vmf)
{

	return __xfs_filemap_fault(vmf, 0, true);
}

static const struct vm_operations_struct xfs_file_vm_ops = {
	.fault		= xfs_filemap_fault,
	.huge_fault	= xfs_filemap_huge_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= xfs_filemap_page_mkwrite,
	.pfn_mkwrite	= xfs_filemap_pfn_mkwrite,
};

STATIC int
xfs_file_mmap(
	struct file		*file,
	struct vm_area_struct	*vma)
{
	struct inode		*inode = file_inode(file);
	struct xfs_buftarg	*target = xfs_inode_buftarg(XFS_I(inode));

	/*
	 * We don't support synchronous mappings for non-DAX files and
	 * for DAX files if underneath dax_device is not synchronous.
	 */
	if (!daxdev_mapping_supported(vma, target->bt_daxdev))
		return -EOPNOTSUPP;

	file_accessed(file);
	vma->vm_ops = &xfs_file_vm_ops;
	if (IS_DAX(inode))
		vm_flags_set(vma, VM_HUGEPAGE);
	return 0;
}

const struct file_operations xfs_file_operations = {
	.llseek		= xfs_file_llseek,
	.read_iter	= xfs_file_read_iter,
	.write_iter	= xfs_file_write_iter,
	.splice_read	= xfs_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.iopoll		= iocb_bio_iopoll,
	.unlocked_ioctl	= xfs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= xfs_file_compat_ioctl,
#endif
	.mmap		= xfs_file_mmap,
	.mmap_supported_flags = MAP_SYNC,
	.open		= xfs_file_open,
	.release	= xfs_file_release,
	.fsync		= xfs_file_fsync,
	.get_unmapped_area = thp_get_unmapped_area,
	.fallocate	= xfs_file_fallocate,
	.fadvise	= xfs_file_fadvise,
	.remap_file_range = xfs_file_remap_range,
};

const struct file_operations xfs_dir_file_operations = {
	.open		= xfs_dir_open,
	.read		= generic_read_dir,
	.iterate_shared	= xfs_file_readdir,
	.llseek		= generic_file_llseek,
	.unlocked_ioctl	= xfs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= xfs_file_compat_ioctl,
#endif
	.fsync		= xfs_dir_fsync,
};
