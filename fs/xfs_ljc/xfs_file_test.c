#include <linux/module.h>
#include <linux/init.h>
#include <linux/xarray.h>
#include <linux/errno.h>
#include <linux/string.h>
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

extern void update_in_xarray(struct xarray *xa, long long key, long long value, ssize_t xaid);
extern void delete_in_xarray(struct xarray *xa, long long key, ssize_t xaid);
extern long long query_in_xarray(struct xarray *xa, long long key, ssize_t xaid);
extern long long range_query_in_xarray_nlogn(struct xarray *xa, long long start_key, long long end_key, long long range_query_result[], ssize_t xaid);
extern ssize_t bio_merge_single_page(int pageid, int page_in_pos,char __user *buf, int len, size_t xaid);
extern void calc_LR_size(size_t user_pos, size_t len, size_t *L_Size, size_t *R_Size);




struct test_ctx {
    int checks;
    int fails;
};

// 测试标签
#define TEST_TAG        "[XXFS-TEST]"
#define TLOG(fmt, ...)  pr_info(TEST_TAG " " fmt, ##__VA_ARGS__)
#define TERR(fmt, ...)  pr_err (TEST_TAG " " fmt, ##__VA_ARGS__)

#define EXPECT_TRUE(ctx, cond) do {                                   \
    (ctx)->checks++;                                                  \
    if (!(cond)) {                                                    \
        (ctx)->fails++;                                               \
        TERR("EXPECT_TRUE failed @%s:%d: %s\n",                       \
             __func__, __LINE__, #cond);                              \
    } else {                                                          \
        TLOG("EXPECT_TRUE passed @%s:%d: %s\n",                       \
             __func__, __LINE__, #cond);                              \
    }                                                                 \
} while (0)

#define EXPECT_EQ(ctx, a, b) do {                                     \
    long long _va = (long long)(a);                                   \
    long long _vb = (long long)(b);                                   \
    (ctx)->checks++;                                                  \
    if (_va != _vb) {                                                 \
        (ctx)->fails++;                                               \
        TERR("EXPECT_EQ failed  @%s:%d: %s != %s  (%lld != %lld)\n",  \
             __func__, __LINE__, #a, #b, _va, _vb);                   \
    } else {                                                          \
        TLOG("EXPECT_EQ passed  @%s:%d: %s == %s  (%lld)\n",          \
             __func__, __LINE__, #a, #b, _va);                        \
    }                                                                 \
} while (0)


typedef void (*test_fn)(struct test_ctx *ctx);


// xarray 单点 key 插入与查询
static void tc_xarray_update_and_query_single_key(struct test_ctx *ctx);
// xarray 查询不存在的 key
static void tc_xarray_query_nonexistent_key(struct test_ctx *ctx);
// xarray 更新 key 查询
static void tc_xarray_update_existing_key(struct test_ctx *ctx); 
// xarray 删除 key 查询
static void tc_xarray_delete_key_and_query(struct test_ctx *ctx);
// xarray 范围 key 更新与查询
static void tc_xarray_range_update_and_query(struct test_ctx *ctx);
// 页碎片合并 单碎片插入测试
static void tc_bio_merge_single_page_single_insert(struct test_ctx *ctx);
// 页碎片合并 相交碎片合并测试
static void tc_bio_merge_single_page_merge_intersect(struct test_ctx *ctx);
// 页碎片合并 相邻碎片合并测试
static void tc_bio_merge_single_page_merge_adjacent(struct test_ctx *ctx);
// 页碎片合并 碎片覆盖测试
static void tc_bio_merge_single_page_merge_cover(struct test_ctx *ctx);
// 页碎片合并 多碎片排序测试
static void tc_bio_merge_single_page_mutiple_insert_and_sort(struct test_ctx *ctx);
// 碎片页计算 单对齐页写入测试
static void tc_calc_LR_size_aligned_write(struct test_ctx *ctx);
// 碎片页计算 多对齐页写入测试
static void tc_calc_LR_size_multi_aligned_write(struct test_ctx *ctx);
// 碎片页计算 右不对齐页写入测试
static void tc_calc_LR_size_right_unaligned_write(struct test_ctx *ctx);
// 碎片页计算 左不对齐页写入测试
static void tc_calc_LR_size_left_unaligned_write(struct test_ctx *ctx);
// 碎片页计算 全不对齐页写入测试
static void tc_calc_LR_size_both_unaligned_write(struct test_ctx *ctx);
// 碎片页计算 小于一页写入测试
static void tc_calc_LR_size_less_than_one_page_write(struct test_ctx *ctx);
// 碎片页计算 跨多页全不对齐页写入测试
static void tc_calc_LR_size_multi_page_both_unaligned_write(struct test_ctx *ctx);
// ready_blade_page_num 计算 满页写入测试
static void tc_ready_blade_page_num_full_page_write(struct test_ctx *ctx);
// ready_blade_page_num 计算 非满页写入测试
static void tc_ready_blade_page_num_non_full_page_write(struct test_ctx *ctx);
// ready_blade_page_num 计算 多满页写入测试
static void tc_ready_blade_page_num_multi_full_page_write(struct test_ctx *ctx);
// ready_blade_page_num 计算 混合写入测试
static void tc_ready_blade_page_num_mixed_page_write(struct test_ctx *ctx);
// unready_blade_page_num 计算 满页写入测试
static void tc_unready_blade_page_num_full_page_write(struct test_ctx *ctx);
// unready_blade_page_num 计算 非满页写入测试
static void tc_unready_blade_page_num_non_full_page_write(struct test_ctx *ctx);
// unready_blade_page_num 计算 混合写入测试
static void tc_unready_blade_page_num_mixed_page_write(struct test_ctx *ctx);

// 用例注册表
static const struct {
    const char *name;
    test_fn fn;
} g_tests[] = {
    { "update_and_query_single_key",   tc_xarray_update_and_query_single_key   },
    { "query_nonexistent_key",         tc_xarray_query_nonexistent_key         },
    { "update_existing_key",           tc_xarray_update_existing_key           },
    { "delete_key_and_query",          tc_xarray_delete_key_and_query          },
    { "range_update_and_query",        tc_xarray_range_update_and_query        },
    { "bio_merge_single_page_single_insert", tc_bio_merge_single_page_single_insert },
    { "bio_merge_single_page_merge_intersect", tc_bio_merge_single_page_merge_intersect },
    { "bio_merge_single_page_merge_adjacent", tc_bio_merge_single_page_merge_adjacent },
    { "bio_merge_single_page_merge_cover", tc_bio_merge_single_page_merge_cover },
    { "bio_merge_single_page_mutiple_insert_and_sort", tc_bio_merge_single_page_mutiple_insert_and_sort },
    { "calc_LR_size_aligned_write",    tc_calc_LR_size_aligned_write    },
    { "calc_LR_size_multi_aligned_write", tc_calc_LR_size_multi_aligned_write },
    { "calc_LR_size_right_unaligned_write", tc_calc_LR_size_right_unaligned_write },
    { "calc_LR_size_left_unaligned_write", tc_calc_LR_size_left_unaligned_write },
    { "calc_LR_size_both_unaligned_write", tc_calc_LR_size_both_unaligned_write },
    { "calc_LR_size_less_than_one_page_write", tc_calc_LR_size_less_than_one_page_write },
    { "calc_LR_size_multi_page_both_unaligned_write", tc_calc_LR_size_multi_page_both_unaligned_write },
    { "ready_blade_page_num_full_page_write", tc_ready_blade_page_num_full_page_write },
    { "ready_blade_page_num_non_full_page_write", tc_ready_blade_page_num_non_full_page_write },
    { "ready_blade_page_num_multi_full_page_write", tc_ready_blade_page_num_multi_full_page_write },
    { "ready_blade_page_num_mixed_page_write", tc_ready_blade_page_num_mixed_page_write },
    { "unready_blade_page_num_full_page_write", tc_unready_blade_page_num_full_page_write },
    { "unready_blade_page_num_non_full_page_write", tc_unready_blade_page_num_non_full_page_write },
    { "unready_blade_page_num_mixed_page_write", tc_unready_blade_page_num_mixed_page_write },
};

// 用例具体实现

// XArray 增删改查逻辑测试
static void tc_xarray_update_and_query_single_key(struct test_ctx *ctx){
    struct xarray xa;
    xa_init(&xa);

    update_in_xarray(&xa, 42, 123, 0);
    EXPECT_EQ(ctx, query_in_xarray(&xa, 42, 0), 123);

    xa_destroy(&xa);
}

static void tc_xarray_query_nonexistent_key(struct test_ctx *ctx){
    struct xarray xa;
    xa_init(&xa);

    EXPECT_EQ(ctx, query_in_xarray(&xa, 99, 0), -1);

    xa_destroy(&xa);
}

static void tc_xarray_update_existing_key(struct test_ctx *ctx){
    struct xarray xa;
    xa_init(&xa);

    update_in_xarray(&xa, 7, 100, 0);
    update_in_xarray(&xa, 7, 200, 0);
    EXPECT_EQ(ctx, query_in_xarray(&xa, 7, 0), 200);

    xa_destroy(&xa);
}

static void tc_xarray_delete_key_and_query(struct test_ctx *ctx){
    struct xarray xa;
    xa_init(&xa);

    update_in_xarray(&xa, 55, 555, 0);
    delete_in_xarray(&xa, 55, 0);
    EXPECT_EQ(ctx, query_in_xarray(&xa, 55, 0), -1);

    xa_destroy(&xa);
}

static void tc_xarray_range_update_and_query(struct test_ctx *ctx){
    struct xarray xa;
    long long results[5] = {0};
    ssize_t count;


    for (long long i = 10; i < 15; i++) {
        update_in_xarray(&xa, i, i * 10, 0); // key 10, value 100; key 11, value 110; ...
    }

    count = range_query_in_xarray_nlogn(&xa, 11, 14, results, 0);
    EXPECT_EQ(ctx, count, 4);
    EXPECT_EQ(ctx, results[0], 110); // key 11
    EXPECT_EQ(ctx, results[1], 120); // key 12
    EXPECT_EQ(ctx, results[2], 130); // key 13
    EXPECT_EQ(ctx, results[3], 140); // key 14

    xa_destroy(&xa);
}

// Scrap Buffer 非对齐页碎片合并逻辑测试
static void tc_bio_merge_single_page_single_insert(struct test_ctx *ctx){
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    // 在 pageid=0, page_in_pos=0 处插入 50 字节数据
    ssize_t len = bio_merge_single_page(0, 0, buf, 50, 0);
    // 检验 allpage_meta 元数据信息是否正确
    EXPECT_EQ(ctx, allpage_meta[0].num, 1);
    EXPECT_EQ(ctx, allpage_meta[0].len[0], 50);
    EXPECT_EQ(ctx, allpage_meta[0].pos[0], 0);

    kfree(buf);
}

static void tc_bio_merge_single_page_merge_intersect(struct test_ctx *ctx){
    char __user *buf = (char __user *)kmalloc(200, GFP_KERNEL);

    // 在 pageid=1, page_in_pos=0 处插入 100 字节数据
    ssize_t len1 = bio_merge_single_page(1, 0, buf, 100, 0);
    // 在 pageid=1, page_in_pos=50 处插入 100 字节数据，与前一个插入操作有重叠
    ssize_t len2 = bio_merge_single_page(1, 50, buf, 100, 0);

    // 检验 allpage_meta 元数据信息是否正确，应该合并为一个片段，长度为 150，起始位置为0
    EXPECT_EQ(ctx, allpage_meta[1].num, 1);
    EXPECT_EQ(ctx, allpage_meta[1].len[0], 150);
    EXPECT_EQ(ctx, allpage_meta[1].pos[0], 0);

    kfree(buf);
}

static void tc_bio_merge_single_page_merge_adjacent(struct test_ctx *ctx){
    char __user *buf = (char __user *)kmalloc(200, GFP_KERNEL);

    // 在 pageid=2, page_in_pos=0 处插入 100 字节数据
    ssize_t len1 = bio_merge_single_page(2, 0, buf, 100, 0);
    // 在 pageid=2, page_in_pos=100 处插入 100 字节数据，与前一个插入操作相邻
    ssize_t len2 = bio_merge_single_page(2, 100, buf, 100, 0);

    // 检验 allpage_meta 元数据信息是否正确，应该合并为一个片段，长度为 200，起始位置为0
    EXPECT_EQ(ctx, allpage_meta[2].num, 1);
    EXPECT_EQ(ctx, allpage_meta[2].len[0], 200);
    EXPECT_EQ(ctx, allpage_meta[2].pos[0], 0);

    kfree(buf);
}

static void tc_bio_merge_single_page_merge_cover(struct test_ctx *ctx){
    char __user *buf = (char __user *)kmalloc(200, GFP_KERNEL);

    // 在 pageid=4, page_in_pos=50 处插入 100 字节数据
    ssize_t len1 = bio_merge_single_page(4, 50, buf, 100, 0);
    // 在 pageid=4, page_in_pos=0 处插入 200 字节数据，覆盖前一个插入操作
    ssize_t len2 = bio_merge_single_page(4, 0, buf, 200, 0);

    // 检验 allpage_meta 元数据信息是否正确，应该合并为一个片段，长度为 200，起始位置为0
    EXPECT_EQ(ctx, allpage_meta[4].num, 1);
    EXPECT_EQ(ctx, allpage_meta[4].len[0], 200);
    EXPECT_EQ(ctx, allpage_meta[4].pos[0], 0);

    kfree(buf);
}

static void tc_bio_merge_single_page_mutiple_insert_and_sort(struct test_ctx *ctx){
    char __user *buf = (char __user *)kmalloc(300, GFP_KERNEL);

    // 在 pageid=3, page_in_pos=100 处插入 50 字节数据
    ssize_t len1 = bio_merge_single_page(3, 100, buf, 50, 0);
    // 在 pageid=3, page_in_pos=0 处插入 50 字节数据
    ssize_t len2 = bio_merge_single_page(3, 0, buf, 50, 0);
    // 在 pageid=3, page_in_pos=200 处插入 50 字节数据
    ssize_t len3 = bio_merge_single_page(3, 200, buf, 50, 0);

    // 检验 allpage_meta 元数据信息是否正确，应该有三个片段，按位置排序
    EXPECT_EQ(ctx, allpage_meta[3].num, 3);
    EXPECT_EQ(ctx, allpage_meta[3].len[0], 50);
    EXPECT_EQ(ctx, allpage_meta[3].pos[0], 0);
    EXPECT_EQ(ctx, allpage_meta[3].len[1], 50);
    EXPECT_EQ(ctx, allpage_meta[3].pos[1], 100);
    EXPECT_EQ(ctx, allpage_meta[3].len[2], 50);
    EXPECT_EQ(ctx, allpage_meta[3].pos[2], 200);

    kfree(buf);
}


// 用户请求对齐切分逻辑测试
static void tc_calc_LR_size_aligned_write(struct test_ctx *ctx){
    size_t L_Size = 0, R_Size = 0;

    // 测试用例：用户写入从 0 开始，长度为 256KB 的数据
    calc_LR_size(0, 256 * 1024, &L_Size, &R_Size);
    EXPECT_EQ(ctx, L_Size, 0);
    EXPECT_EQ(ctx, R_Size, 0);
}

static void tc_calc_LR_size_multi_aligned_write(struct test_ctx *ctx){
    size_t L_Size = 0, R_Size = 0;

    // 测试用例：用户写入从 512KB 开始，长度为 512KB 的数据
    calc_LR_size(512 * 1024, 512 * 1024, &L_Size, &R_Size);
    EXPECT_EQ(ctx, L_Size, 0);
    EXPECT_EQ(ctx, R_Size, 0);
}

static void tc_calc_LR_size_right_unaligned_write(struct test_ctx *ctx){
    size_t L_Size = 0, R_Size = 0;

    // 测试用例：用户写入从 0 开始，长度为 300KB 的数据
    calc_LR_size(0, 300 * 1024, &L_Size, &R_Size);
    EXPECT_EQ(ctx, L_Size, 0);
    EXPECT_EQ(ctx, R_Size, 44 * 1024);
}

static void tc_calc_LR_size_left_unaligned_write(struct test_ctx *ctx){
    size_t L_Size = 0, R_Size = 0;

    // 测试用例：用户写入从 100KB 开始，长度为 412KB 的数据
    calc_LR_size(100 * 1024, 412 * 1024, &L_Size, &R_Size);
    EXPECT_EQ(ctx, L_Size, 156 * 1024);
    EXPECT_EQ(ctx, R_Size, 0);
}

static void tc_calc_LR_size_both_unaligned_write(struct test_ctx *ctx){
    size_t L_Size = 0, R_Size = 0;

    // 测试用例：用户写入从 100KB 开始，长度为 300KB 的数据
    calc_LR_size(100 * 1024, 300 * 1024, &L_Size, &R_Size);
    EXPECT_EQ(ctx, L_Size, 156 * 1024);
    EXPECT_EQ(ctx, R_Size, 144 * 1024);
}

static void tc_calc_LR_size_less_than_one_page_write(struct test_ctx *ctx){
    size_t L_Size = 0, R_Size = 0;

    // 测试用例：用户写入从 50KB 开始，长度为 100KB 的数据
    calc_LR_size(50 * 1024, 100 * 1024, &L_Size, &R_Size);
    EXPECT_EQ(ctx, L_Size, 100 * 1024);
    EXPECT_EQ(ctx, R_Size, 0);
}

static void tc_calc_LR_size_multi_page_both_unaligned_write(struct test_ctx *ctx){
    size_t L_Size = 0, R_Size = 0;

    // 测试用例：用户写入从 100KB 开始，长度为 600KB 的数据
    calc_LR_size(100 * 1024, 600 * 1024, &L_Size, &R_Size);
    EXPECT_EQ(ctx, L_Size, 156 * 1024);
    EXPECT_EQ(ctx, R_Size, 188 * 1024);

}

// FLUSH 双端队列维护满页、非满页逻辑测试
static void tc_ready_blade_page_num_full_page_write(struct test_ctx *ctx){
    atomic_set(ready_blade_page_num, 0);
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    bio_merge_single_page(0, 0, buf, 256 * 1024, 0); // 写入满页数据

    // 测试用例：写入满页数据
    EXPECT_EQ(ctx, atomic_read(ready_blade_page_num), 1);
}

static void tc_ready_blade_page_num_non_full_page_write(struct test_ctx *ctx){
    atomic_set(ready_blade_page_num, 0);
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    bio_merge_single_page(1, 0, buf, 100 * 1024, 0); // 写入非满页数据

    // 测试用例：写入非满页数据
    EXPECT_EQ(ctx, atomic_read(ready_blade_page_num), 0);
}

static void tc_ready_blade_page_num_multi_full_page_write(struct test_ctx *ctx){
    atomic_set(ready_blade_page_num, 0);
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    bio_merge_single_page(2, 0, buf, 256 * 1024, 0); // 写入满页数据
    bio_merge_single_page(3, 0, buf, 256 * 1024, 0); // 写入满页数据
    bio_merge_single_page(4, 0, buf, 256 * 1024, 0); // 写入满页数据
    bio_merge_single_page(5, 0, buf, 256 * 1024, 0); // 写入满页数据

    // 测试用例：写入多页满页数据
    EXPECT_EQ(ctx, atomic_read(ready_blade_page_num), 4);
}

static void tc_ready_blade_page_num_mixed_page_write(struct test_ctx *ctx){
    atomic_set(ready_blade_page_num, 0);
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    bio_merge_single_page(6, 0, buf, 256 * 1024, 0); // 写入满页数据
    bio_merge_single_page(7, 0, buf, 100 * 1024, 0); // 写入非满页数据
    bio_merge_single_page(8, 0, buf, 44 * 1024, 0); // 写入非满页数据
    bio_merge_single_page(9, 0, buf, 133 * 1024, 0); // 写入非满页数据
    bio_merge_single_page(10, 0, buf, 256 * 1024, 0); // 写入满页数据

    // 测试用例：写入混合页数据
    EXPECT_EQ(ctx, atomic_read(ready_blade_page_num), 2);

}

static void tc_unready_blade_page_num_full_page_write(struct test_ctx *ctx){
    atomic_set(unready_blade_page_num, 0);
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    bio_merge_single_page(11, 0, buf, 256 * 1024, 0); // 写入满页数据

    // 测试用例：写入满页数据
    EXPECT_EQ(ctx, atomic_read(unready_blade_page_num), 0);
}

static void tc_unready_blade_page_num_non_full_page_write(struct test_ctx *ctx){
    atomic_set(unready_blade_page_num, 0);
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    bio_merge_single_page(12, 0, buf, 100 * 1024, 0); // 写入非满页数据

    // 测试用例：写入非满页数据
    EXPECT_EQ(ctx, atomic_read(unready_blade_page_num), 1);
}

static void tc_unready_blade_page_num_mixed_page_write(struct test_ctx *ctx){
    atomic_set(unready_blade_page_num, 0);
    char __user *buf = (char __user *)kmalloc(100, GFP_KERNEL);

    bio_merge_single_page(13, 0, buf, 256 * 1024, 0); // 写入满页数据
    bio_merge_single_page(14, 0, buf, 100 * 1024, 0); // 写入非满页数据
    bio_merge_single_page(15, 0, buf, 108 * 1024, 0); // 写入非满页数据
    bio_merge_single_page(16, 0, buf, 94 * 1024, 0); // 写入非满页数据
    bio_merge_single_page(17, 0, buf, 256 * 1024, 0); // 写入满页数据

    // 测试用例：写入混合页数据
    EXPECT_EQ(ctx, atomic_read(unready_blade_page_num), 3);

}



// 模块参数 filter= 用例名，只运行匹配的用例
static char *filter;
module_param(filter, charp, 0644);
MODULE_PARM_DESC(filter, "Run only the test with this name (exact match)");

static int __init test_init(void)
{
    int i, matched = 0;
    int total_checks = 0, total_fails = 0;

    TLOG("Begin tests: %zu cases%s%s\n",
         ARRAY_SIZE(g_tests),
         filter ? " (filter=" : "",
         filter ? filter : "");

    for (i = 0; i < ARRAY_SIZE(g_tests); ++i) {
        struct test_ctx ctx = {0};

        if (filter && strcmp(filter, g_tests[i].name) != 0)
            continue;

        matched++;
        TLOG("RUN  [%02d/%02zu] %s\n",
             i + 1, ARRAY_SIZE(g_tests), g_tests[i].name);

        g_tests[i].fn(&ctx);

        TLOG("DONE [%02d/%02zu] %s : checks=%d fails=%d\n",
             i + 1, ARRAY_SIZE(g_tests), g_tests[i].name, ctx.checks, ctx.fails);

        total_checks += ctx.checks;
        total_fails  += ctx.fails;
    }

    if (filter && matched == 0) {
        TERR("No test matched filter='%s'\n", filter);
        return -EINVAL;
    }

    if (total_fails == 0) {
        TLOG("ALL PASSED ✓  (checks=%d, ran=%d/%zu cases)\n",
             total_checks, matched ? matched : (int)ARRAY_SIZE(g_tests),
             ARRAY_SIZE(g_tests));
        // 加载成功，后续手动 rmmod 卸载
        return 0;          
    } else {
        TERR("FAILED ✗  (checks=%d fails=%d, ran=%d/%zu cases)\n",
             total_checks, total_fails,
             matched ? matched : (int)ARRAY_SIZE(g_tests),
             ARRAY_SIZE(g_tests));
        // 失败则返回错误码
        return -EINVAL;    
    }
}

static void __exit test_exit(void) { }
module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("XFS unit tests for query_in_xarray()");
