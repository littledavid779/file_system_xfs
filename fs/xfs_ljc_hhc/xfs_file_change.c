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

static const struct vm_operations_struct xfs_file_vm_ops;

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

STATIC ssize_t
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

STATIC ssize_t
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
// #define XXFS


STATIC ssize_t
xfs_file_read_iter(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct inode		*inode = file_inode(iocb->ki_filp);
	struct xfs_mount	*mp = XFS_I(inode)->i_mount;
	ssize_t			ret = 0;

	XFS_STATS_INC(mp, xs_read_calls);

	if (xfs_is_shutdown(mp))
		return -EIO;

// #ifdef XXFS
// 	//modify
// 	iocb->ki_flags |= IOCB_DIRECT;
// 	size_t L_Size = iocb.ki_pos%Aligned_Size;
// 	size_t R_Size = (iocb.ki_pos + from->count)%Aligned_Size;
// 	size_t flag;
// 	ASSERT(L_Size >= 0);
// 	ASSERT(R_Size >= 0);
// 	if(L_Size == 0 && R_Size == 0){
// 		flag = 0;
// 		ret = 0;
// 	}
// 	else if(R_Size == 0){
// 		flag = 1;
// 		ret = xxfs_bio_write(iocb.ki_pos, from->ubuf, L_Size, flag);
// 	}
// 	else if(L_Size == 0){
// 		flag = 2;
// 		ret = xxfs_bio_write(iocb.ki_pos + from->count - R_Size, from->ubuf, R_Size, flag);
// 	}
// 	else if(L_Size + R_Size == from->count){
// 		flag = 3;
// 		ret = xxfs_bio_write(iocb.ki_pos, from->ubuf, L_Size + R_Size, flag);
// 		goto io_done;
// 	}
// 	else{
// 		flag = 4;
// 		ret = xxfs_bio_write(iocb.ki_pos, from->ubuf, L_Size, flag);
// 		ret += xxfs_bio_write(iocb.ki_pos + from->count - R_Size, from->ubuf, R_Size, flag);
// 	}


// 	void *dio_buf = kvalloc(sizeof(from->ubuf) - L_Size - R_Size);
// 	memcpy(from->ubuf + L_Size,dio_buf,from->count - L_Size - R_Size);
// 	iocb.ki_pos = iocb.ki_pos - L_Size;
// 	from->ubuf = dio_buf;
	
// 	if (iocb->ki_flags & IOCB_DIRECT) {
// 		/*
// 		 * Allow a directio write to fall back to a buffered
// 		 * write *only* in the case that we're doing a reflink
// 		 * CoW.  In all other directio scenarios we do not
// 		 * allow an operation to fall back to buffered mode.
// 		 */
// 		ssize_t tmp;
// 		tmp = xfs_file_dio_write(iocb, from);
// 		free(dio_buf);
// 		if (tmp != -ENOTBLK)
// 			return ret + tmp;
// 	}

// io_done:
// 	return ret;
	

// #endif

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
	ret = xfs_file_write_checks(iocb, from, &iolock);
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

static ssize_t
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


#define XXFS

#ifdef XXFS
#define Aligned_Size 16*1024
#define Memory_Size 10ll*1024*1024*1024
void *memorycache=NULL;

int blade_page_bitmap[100005];
int blade_page_pos=0;

void init_memory_cache(size_t size)
{
	memorycache = vmalloc(size);
	ASSERT(memorycache);
	return ;
}

struct blade_page
{
	unsigned short pos[256];
	unsigned short len[255];
	unsigned short num;
	char data[Aligned_Size];
}*allpage;

int alloc_blade_page()
{
	while(blade_page_bitmap[blade_page_pos])
	{
		blade_page_pos++;
	}
	allpage[blade_page_pos].num=0;
	return blade_page_pos;
}

#define MAX_PAGE_UPDATES 16
struct bladepageinfo
{
	int pos;
	int size;
}pageinfo[MAX_PAGE_UPDATES];


size_t bio_merge_single_page(int pageid, int num, int page_in_pos, const char __user *buf, int len)
{
    if(num == 0){
        pageinfo[0].pos = page_in_pos;
        pageinfo[0].size = len;
        return 1; 
    }
	//do_io directly

    int idxL = num, idxR = -1;
    for(int i = 0;i < num;i++){
        if(pageinfo[i].pos <= page_in_pos + len - 1 && pageinfo[i].pos + pageinfo[i].size - 1 >= page_in_pos){
            if(idxL > i) idxL = i;
            if(idxR < i) idxR = i;
        }
    }
    struct bladepageinfo new_pageinfo;

    int minL = page_in_pos,maxR = page_in_pos + len - 1;

    for(int i = idxL;i <= idxR; i++)
	{
        if(pageinfo[i].pos < minL) minL = pageinfo[i].pos;
        if(pageinfo[i].pos + pageinfo[i].size - 1 > maxR) maxR = pageinfo[i].pos + pageinfo[i].size - 1;
    }

    new_pageinfo.pos = minL;
    new_pageinfo.size = maxR - minL + 1;

    int tail = idxL;
    if(idxL > idxR)
	{
        if(page_in_pos < pageinfo[0].pos)
		{
            for(int i = num - 1;i >= 0;i--)
			{
                pageinfo[i + 1] = pageinfo[i];
            }
            pageinfo[0] = new_pageinfo;
        }
        else 
		{
            pageinfo[num] = new_pageinfo;
        }
        return num + 1;
    }

    pageinfo[tail++] = new_pageinfo;

    for(int i = idxR + 1;i < num;i++){
        pageinfo[tail++] = pageinfo[i];
    }

	allpage[pageid].num = num - idxR + idxL;

    return num;
}


int lookup_blade_page(size_t pos)
{
	return 0;
}


inline size_t xxfs_bio_write(size_t pos, const char __user *buf, size_t len, size_t flag)
{	
	if(!memorycache)
		alloc_memory_cache(Memory_Size);
	allpage = memorycache;

	size_t ret = 0;
	// if(ava_space < len){
	// 	wait;// 争哪种锁？
	// }
	// atomic sub ava_space len;
	// // 记得上范围锁
	
	if(flag == 3)
	{
		//考虑合并分配和查找的逻辑
		int nowpage1 = lookup_blade_page(pos);
		int nowpage2 = lookup_blade_page(pos+len);
		if(nowpage1<0)
		{
			nowpage1 = alloc_blade_page();
			insert_blade_page(nowpage1);
		}
		if(nowpage2<0)
		{
			nowpage2 = alloc_blade_page();
			insert_blade_page(nowpage2);
		}
		// ret = bio_merge_two_page(nowpage1,nowpage2);
		size_t L_Size;
		size_t L_Size = Aligned_Size - pos%Aligned_Size;
		ret = bio_merge_single_page(nowpage1, pos%Aligned_Size, buf, L_Size);
		ret += bio_merge_single_page(nowpage2, 0, buf+L_Size, len-L_Size);
	}
	else
	{
		int nowpage=lookup_blade_page(pos);
		if(nowpage<0)
			nowpage = alloc_blade_page();
		ret = bio_merge_single_page(nowpage, pos%Aligned_Size, buf, len);
	}

	// 做完解锁
	// 此时xxfs并没有分配数据块

	return ret;
}

//对于Stripe AFA,采用Stripe Aligned刷
//对于Two-phase AFA,采用SSD-Page Aligned刷
//维护数据结构快速确定满块
//维护多个flushing线程，根据忙碌情况自适应下刷
void xxfs_flushing()
{
	// if(ava_space <= flush_threshold)
	// {
		// 预计走dio逻辑去flushing并分配数据块，尚不清楚存在什么隐患

		// 读修改写，需要考虑锁

		// 何时释放？
	// }
	return ;
}


#endif


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

	if (ocount == 0)
		return 0;

	if (xfs_is_shutdown(ip->i_mount))
		return -EIO;

	if (IS_DAX(inode))
		return xfs_file_dax_write(iocb, from);

#ifdef XXFS
	//modify
	printk("*******************************\n");
	printk("!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printk("ocount = %ld\n",ocount);
	iocb->ki_flags |= IOCB_DIRECT;
	size_t L_Size, R_Size;
	if((iocb->ki_pos/Aligned_Size)==((iocb->ki_pos+from->count)/Aligned_Size)) //请求在一个blade page中
	{
		L_Size = from->count;
		R_Size = 0;
	}
	else
	{
		L_Size = Aligned_Size - iocb->ki_pos%Aligned_Size;
		if(L_Size == Aligned_Size)
			L_Size = 0;
		R_Size = (iocb->ki_pos + from->count)%Aligned_Size;
	}

	size_t flag;
	ASSERT(L_Size >= 0);
	ASSERT(R_Size >= 0);
	if(L_Size == 0 && R_Size == 0){
		flag = 0;
		ret = 0;
		printk("********************************************");
		printk("pass-flag-0");
		printk("********************************************");
	}
	else if(R_Size == 0){
		flag = 1;
		ret = xxfs_bio_write(iocb->ki_pos, from->ubuf, L_Size, flag);
		printk("********************************************");
		printk("pass-flag-1");
		printk("********************************************");
	}
	else if(L_Size == 0){
		flag = 2;
		ret = xxfs_bio_write(iocb->ki_pos + from->count - R_Size, from->ubuf, R_Size, flag);
		printk("********************************************");
		printk("pass-flag-2");
		printk("********************************************");
	}
	else if(L_Size + R_Size == from->count){
		flag = 3;
		ret = xxfs_bio_write(iocb->ki_pos, from->ubuf, L_Size + R_Size, flag);
		printk("********************************************");
		printk("pass-flag-3");
		printk("********************************************");
		goto io_done;
	}
	else{
		flag = 4;
		ret = xxfs_bio_write(iocb->ki_pos, from->ubuf, L_Size, flag);
		ret += xxfs_bio_write(iocb->ki_pos + from->count - R_Size, from->ubuf, R_Size, flag);
		printk("********************************************");
		printk("pass-flag-4 ");
		printk("********************************************");
	}

	// void *dio_buf = kvalloc(sizeof(from->ubuf) - L_Size - R_Size);
	// memcpy(from->ubuf + L_Size,dio_buf,from->count - L_Size - R_Size);

	// iocb->ki_pos = iocb->ki_pos - L_Size;
	// from->ubuf = dio_buf;

	// 获取第一个 iovec，并确定用户空间缓冲区的起始地址和大小
	size_t buf_size = iov_iter_count(from);
	printk("********************************************\n");
	printk("buf_size = %ld, L_Size = %ld, R_Size = %ld\n",buf_size,L_Size,R_Size);
	printk("********************************************\n");

	// 分配大小为 buf_size - L_Size - R_Size 的缓冲区
	void *dio_buf = vmalloc(buf_size - L_Size - R_Size);
	if(!dio_buf){
		printk("********************************************\n");
		printk("fault-dio_buf-wrong!!!!!!!!! ");
		printk("********************************************\n");
	 }
	// memcpy(from->ubuf + L_Size,dio_buf,from->count - L_Size - R_Size);

	copy_from_user(dio_buf, from->ubuf + L_Size,buf_size - L_Size - R_Size);
	

	// 调整 iocb->ki_pos，更新用户空间缓冲区指针
	iocb->ki_pos = iocb->ki_pos - L_Size;
	from->ubuf = dio_buf;


	// printk("********************************************");
	// printk("diobuf = %s, buf_size = %ld, L_Size = %ld, R_Size = %ld",dio_buf,buf_size,L_Size,R_Size);
	// printk("********************************************");

	// iocb->ki_pos = iocb->ki_pos - L_Size;
	// from->ubuf = dio_buf;
	
	
	if (iocb->ki_flags & IOCB_DIRECT) 
	{
		/*
		 * Allow a directio write to fall back to a buffered
		 * write *only* in the case that we're doing a reflink
		 * CoW.  In all other directio scenarios we do not
		 * allow an operation to fall back to buffered mode.
		 */
		ssize_t tmp;
		tmp = xfs_file_dio_write(iocb, from);
		vfree(dio_buf);
		if (tmp != -ENOTBLK)
			return ret + tmp;
		// if (ret != -ENOTBLK)
		// 	return ret;
	}

io_done:
	return ret;
	

#endif


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
