/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (C) 2016 Gvozden Nešković. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/types.h>
#include <sys/zio.h>
#include <sys/debug.h>
#include <sys/zfs_debug.h>

#include <sys/vdev_raidz.h>
#include <sys/vdev_raidz_impl.h>

/* All compiled in implementations */
const raidz_impl_ops_t *raidz_all_maths[] = {
	&vdev_raidz_scalar_impl,
#if defined(__x86_64) && defined(HAVE_SSE2)	/* only x86_64 for now */
	&vdev_raidz_sse2_impl,
#endif
#if defined(__x86_64) && defined(HAVE_SSSE3)	/* only x86_64 for now */
	&vdev_raidz_ssse3_impl,
#endif
#if defined(__x86_64) && defined(HAVE_AVX2)	/* only x86_64 for now */
	&vdev_raidz_avx2_impl
#endif
};

/* Indicate that benchmark has been completed */
static boolean_t raidz_math_initialized = B_FALSE;

/* Select raidz implementation */
static enum vdev_raidz_impl_sel {
	IMPL_FASTEST	= -1,
	IMPL_ORIGINAL	= -2,
	IMPL_CYCLE	= -3,
	IMPL_SCALAR	=  0,
} zfs_vdev_raidz_impl = IMPL_SCALAR, user_sel_impl = IMPL_FASTEST;

/* selected implementation lock */
static krwlock_t vdev_raidz_impl_lock;

/* RAIDZ op that contain the fastest routines */
static raidz_impl_ops_t vdev_raidz_fastest_impl = {
	.name = "fastest"
};

/* Hold all supported implementations */
size_t raidz_supp_impl_cnt = 1;
raidz_impl_ops_t *raidz_supp_impl[ARRAY_SIZE(raidz_all_maths) + 1] = {
	(raidz_impl_ops_t *) &vdev_raidz_scalar_impl, /* scalar is supported */
	NULL
};

/*
 * kstats values for supported impl + original and fastest methods
 * Values represent per disk throughput of 8 disk+parity raidz vdev (Bps)
 */
static raidz_impl_kstat_t raidz_impl_kstats[ARRAY_SIZE(raidz_all_maths) + 2];

/* kstat for benchmarked implementations */
static kstat_t *raidz_math_kstat = NULL;

/*
 * Selects the raidz operation for raidz_map
 * If rm_ops is set to NULL original raidz implementation will be used
 */
raidz_impl_ops_t *
vdev_raidz_math_get_ops()
{
	raidz_impl_ops_t *ops = NULL;

	rw_enter(&vdev_raidz_impl_lock, RW_READER);

	switch (zfs_vdev_raidz_impl) {
	case IMPL_FASTEST:
		ASSERT(raidz_math_initialized);
		ops = &vdev_raidz_fastest_impl;
		break;
	case IMPL_ORIGINAL:
		ops = NULL;
		break;
#if !defined(_KERNEL)
	case IMPL_CYCLE:
	{
		/*
		 * Cycle through all supported implementations
		 * note: raidz_supp_impl[raidz_supp_impl_cnt] == NULL, in which
		 * case the original implementation is used
		 */
		static size_t cycle_impl_idx = 0;
		size_t idx = (++cycle_impl_idx) % (raidz_supp_impl_cnt + 1);
		ops = raidz_supp_impl[idx];
	}
	break;
#endif
	case IMPL_SCALAR:
		ops = (raidz_impl_ops_t *) &vdev_raidz_scalar_impl;
		break;
	default:
		ASSERT3U(zfs_vdev_raidz_impl, >=, 0);
		ASSERT3U(zfs_vdev_raidz_impl, <, raidz_supp_impl_cnt);
		ops = raidz_supp_impl[zfs_vdev_raidz_impl];
		break;
	}

	rw_exit(&vdev_raidz_impl_lock);

	return (ops);
}

/*
 * Select parity generation method for raidz_map
 */
void
vdev_raidz_math_generate(raidz_map_t *rm)
{
	raidz_gen_f gen_parity = NULL;

	switch (raidz_parity(rm)) {
		case 1:
			gen_parity = rm->rm_ops->gen[RAIDZ_GEN_P];
			break;
		case 2:
			gen_parity = rm->rm_ops->gen[RAIDZ_GEN_PQ];
			break;
		case 3:
			gen_parity = rm->rm_ops->gen[RAIDZ_GEN_PQR];
			break;
		default:
			gen_parity = NULL;
			cmn_err(CE_PANIC, "invalid RAID-Z configuration %d",
				raidz_parity(rm));
			break;
	}

	ASSERT(gen_parity != NULL);

	gen_parity(rm);
}

static raidz_rec_f
_reconstruct_fun_raidz1(raidz_map_t *rm, const int *parity_valid,
	const int nbaddata)
{
	if (nbaddata == 1 && parity_valid[CODE_P]) {
		return (rm->rm_ops->rec[RAIDZ_REC_P]);
	}
	return ((raidz_rec_f) NULL);
}

static raidz_rec_f
_reconstruct_fun_raidz2(raidz_map_t *rm, const int *parity_valid,
	const int nbaddata)
{
	if (nbaddata == 1) {
		if (parity_valid[CODE_P]) {
			return (rm->rm_ops->rec[RAIDZ_REC_P]);
		} else if (parity_valid[CODE_Q]) {
			return (rm->rm_ops->rec[RAIDZ_REC_Q]);
		}
	} else if (nbaddata == 2 &&
		parity_valid[CODE_P] && parity_valid[CODE_Q]) {
		return (rm->rm_ops->rec[RAIDZ_REC_PQ]);
	}
	return ((raidz_rec_f) NULL);
}

static raidz_rec_f
_reconstruct_fun_raidz3(raidz_map_t *rm, const int *parity_valid,
	const int nbaddata)
{
	if (nbaddata == 1) {
		if (parity_valid[CODE_P]) {
			return (rm->rm_ops->rec[RAIDZ_REC_P]);
		} else if (parity_valid[CODE_Q]) {
			return (rm->rm_ops->rec[RAIDZ_REC_Q]);
		} else if (parity_valid[CODE_R]) {
			return (rm->rm_ops->rec[RAIDZ_REC_R]);
		}
	} else if (nbaddata == 2) {
		if (parity_valid[CODE_P] && parity_valid[CODE_Q]) {
			return (rm->rm_ops->rec[RAIDZ_REC_PQ]);
		} else if (parity_valid[CODE_P] && parity_valid[CODE_R]) {
			return (rm->rm_ops->rec[RAIDZ_REC_PR]);
		} else if (parity_valid[CODE_Q] && parity_valid[CODE_R]) {
			return (rm->rm_ops->rec[RAIDZ_REC_QR]);
		}
	} else if (nbaddata == 3 &&
		parity_valid[CODE_P] && parity_valid[CODE_Q] &&
		parity_valid[CODE_R]) {
		return (rm->rm_ops->rec[RAIDZ_REC_PQR]);
	}
	return ((raidz_rec_f) NULL);
}

/*
 * Select data reconstruction method for raidz_map
 * @parity_valid - Parity validity flag
 * @dt           - Failed data index array
 * @nbaddata     - Number of failed data columns
 */
int
vdev_raidz_math_reconstruct(raidz_map_t *rm, const int *parity_valid,
	const int *dt, const int nbaddata)
{
	raidz_rec_f rec_data = NULL;

	switch (raidz_parity(rm)) {
		case 1:
			rec_data = _reconstruct_fun_raidz1(rm, parity_valid,
			    nbaddata);
			break;
		case 2:
			rec_data = _reconstruct_fun_raidz2(rm, parity_valid,
			    nbaddata);
			break;
		case 3:
			rec_data = _reconstruct_fun_raidz3(rm, parity_valid,
			    nbaddata);
			break;
		default:
			cmn_err(CE_PANIC, "invalid RAID-Z configuration %d",
			    raidz_parity(rm));
			break;
	}

	ASSERT(rec_data != NULL);

	return (rec_data(rm, dt));
}

const char *raidz_gen_name[] = {
	"gen_p", "gen_pq", "gen_pqr"
};
const char *raidz_rec_name[] = {
	"rec_p", "rec_q", "rec_r",
	"rec_pq", "rec_pr", "rec_qr", "rec_pqr"
};

static void
init_raidz_kstat(raidz_impl_kstat_t *rs, const char *name)
{
	static uint64_t id = 0;
	char buf[KSTAT_STRLEN];
	int i;

	for (i = 0; i < RAIDZ_GEN_NUM; i++) {
		strlcpy(buf, name, KSTAT_STRLEN);
		strlcat(buf, "_", KSTAT_STRLEN);
		strlcat(buf, raidz_gen_name[i], KSTAT_STRLEN);

		/* method id */
		strlcpy(rs->gen[2 * i].name, buf, KSTAT_STRLEN);
		strlcat(rs->gen[2 * i].name, "_id", KSTAT_STRLEN);
		rs->gen[2 * i].data_type = KSTAT_DATA_UINT64;
		RAIDZ_IMPL_GEN_ID(rs, i) = id++;

		/* method bw */
		strlcpy(rs->gen[2 * i + 1].name, buf, KSTAT_STRLEN);
		strlcat(rs->gen[2 * i + 1].name, "_bw", KSTAT_STRLEN);
		rs->gen[2 * i + 1].data_type = KSTAT_DATA_UINT64;
		RAIDZ_IMPL_GEN_BW(rs, i)  = 0;
	}

	for (i = 0; i < RAIDZ_REC_NUM; i++) {
		strlcpy(buf, name, KSTAT_STRLEN);
		strlcat(buf, "_", KSTAT_STRLEN);
		strlcat(buf, raidz_rec_name[i], KSTAT_STRLEN);

		/* method id */
		strlcpy(rs->rec[2 * i].name, buf, KSTAT_STRLEN);
		strlcat(rs->rec[2 * i].name, "_id", KSTAT_STRLEN);
		rs->rec[2 * i].data_type = KSTAT_DATA_UINT64;
		RAIDZ_IMPL_REC_ID(rs, i) = id++;

		/* method bw */
		strlcpy(rs->rec[2 * i + 1].name, buf, KSTAT_STRLEN);
		strlcat(rs->rec[2 * i + 1].name, "_bw", KSTAT_STRLEN);
		rs->rec[2 * i + 1].data_type = KSTAT_DATA_UINT64;
		RAIDZ_IMPL_REC_BW(rs, i)  = 0;
	}
}

#define	BENCH_D_COLS	(8ULL)
#define	BENCH_COLS	(BENCH_D_COLS + PARITY_PQR)
#define	BENCH_ZIO_SIZE	(1ULL << SPA_OLD_MAXBLOCKSHIFT)	/* 128 kiB */
#define	BENCH_NS	MSEC2NSEC(25)			/* 25ms */

typedef void (*benchmark_fn)(raidz_map_t *rm, const int fn);

static void
benchmark_gen_impl(raidz_map_t *rm, const int fn)
{
	(void) fn;
	vdev_raidz_generate_parity(rm);
}

static void
benchmark_rec_impl(raidz_map_t *rm, const int fn)
{
	static const int rec_tgt[7][3] = {
		{1, 2, 3},	/* rec_p:   bad QR & D[0]	*/
		{0, 2, 3},	/* rec_q:   bad PR & D[0]	*/
		{0, 1, 3},	/* rec_r:   bad PQ & D[0]	*/
		{2, 3, 4},	/* rec_pq:  bad R  & D[0][1]	*/
		{1, 3, 4},	/* rec_pr:  bad Q  & D[0][1]	*/
		{0, 3, 4},	/* rec_qr:  bad P  & D[0][1]	*/
		{3, 4, 5}	/* rec_pqr: bad    & D[0][1][2] */
	};

	vdev_raidz_reconstruct(rm, rec_tgt[fn], 3);
}

/*
 * Benchmarking of all supported implementations (raidz_supp_impl_cnt)
 * is performed by setting the rm_ops pointer and calling the top level
 * generate/reconstruct methods of bench_rm.
 */
static void
benchmark_raidz_impl(raidz_map_t *bench_rm, const int fn, benchmark_fn bench_fn)
{
	uint64_t run_cnt, speed, best_speed = 0;
	hrtime_t t_start, t_diff;
	raidz_impl_ops_t *curr_impl;
	int impl, i;
	raidz_impl_kstat_t *fkstat = (raidz_impl_kstats +
	    raidz_supp_impl_cnt + 1);

	/*
	 * Use the sentinel (NULL) from the end of raidz_supp_impl_cnt
	 * to run "original" implementation (bench_rm->rm_ops = NULL)
	 */
	for (impl = 0; impl <= raidz_supp_impl_cnt; impl++) {
		raidz_impl_kstat_t *ckstat = raidz_impl_kstats + impl;
		/* set an implementation to benchmark */
		curr_impl = raidz_supp_impl[impl];
		bench_rm->rm_ops = curr_impl;

		run_cnt = 0;
		t_start = gethrtime();

		do {
			for (i = 0; i < 25; i++, run_cnt++)
				bench_fn(bench_rm, fn);

			t_diff = gethrtime() - t_start;
		} while (t_diff < BENCH_NS);

		speed = run_cnt * BENCH_ZIO_SIZE * NANOSEC;
		speed /= (t_diff * BENCH_COLS);

		if (bench_fn == benchmark_gen_impl)
			RAIDZ_IMPL_GEN_BW(ckstat, fn) = speed;
		else
			RAIDZ_IMPL_REC_BW(ckstat, fn) = speed;

		/* if curr_impl==NULL the original impl is benchmarked */
		if (curr_impl != NULL && speed > best_speed) {
			best_speed = speed;

			if (bench_fn == benchmark_gen_impl) {
				vdev_raidz_fastest_impl.gen[fn] =
				    curr_impl->gen[fn];
				RAIDZ_IMPL_GEN_ID(fkstat, fn) =
				    RAIDZ_IMPL_GEN_ID(ckstat, fn);
				RAIDZ_IMPL_GEN_BW(fkstat, fn) = speed;
			} else {
				vdev_raidz_fastest_impl.rec[fn] =
				    curr_impl->rec[fn];
				RAIDZ_IMPL_REC_ID(fkstat, fn) =
				    RAIDZ_IMPL_REC_ID(ckstat, fn);
				RAIDZ_IMPL_REC_BW(fkstat, fn) = speed;
			}
		}
	}
}

void
vdev_raidz_math_init(void)
{
	raidz_impl_ops_t *curr_impl;
	zio_t *bench_zio = NULL;
	raidz_map_t *bench_rm = NULL;
	uint64_t bench_parity;
	int i, c, fn;

	/* init & vdev_raidz_impl_lock */
	rw_init(&vdev_raidz_impl_lock, NULL, RW_DEFAULT, NULL);

	/* move supported impl into raidz_supp_impl */
	for (i = 0, c = 0; i < ARRAY_SIZE(raidz_all_maths); i++) {
		curr_impl = (raidz_impl_ops_t *) raidz_all_maths[i];

		/* initialize impl */
		if (curr_impl->init)
			curr_impl->init();

		if (curr_impl->is_supported()) {
			/* init kstat */
			init_raidz_kstat(&raidz_impl_kstats[c],
			    curr_impl->name);
			raidz_supp_impl[c++] = (raidz_impl_ops_t *) curr_impl;
		}
	}
	raidz_supp_impl_cnt = c;	/* number of supported impl */
	raidz_supp_impl[c] = NULL;	/* sentinel */

	/* init kstat for original and fastest routines */
	init_raidz_kstat(&(raidz_impl_kstats[raidz_supp_impl_cnt]),
	    "original");
	init_raidz_kstat(&(raidz_impl_kstats[raidz_supp_impl_cnt + 1]),
	    "fastest");

#if !defined(_KERNEL)
	/*
	 * Skip benchmarking and use last implementation as fastest
	 */
	memcpy(&vdev_raidz_fastest_impl, raidz_supp_impl[raidz_supp_impl_cnt-1],
	    sizeof (vdev_raidz_fastest_impl));

	strcpy(vdev_raidz_fastest_impl.name, "fastest");

	raidz_math_initialized = B_TRUE;

	/* Use 'cycle' math selection method for userspace */
	VERIFY0(vdev_raidz_impl_set("cycle"));
	return;
#endif

	/* Fake an zio and run the benchmark on it */
	bench_zio = kmem_zalloc(sizeof (zio_t), KM_SLEEP);
	bench_zio->io_offset = 0;
	bench_zio->io_size = BENCH_ZIO_SIZE; /* only data columns */
	bench_zio->io_data = zio_data_buf_alloc(BENCH_ZIO_SIZE);
	VERIFY(bench_zio->io_data);
	memset(bench_zio->io_data, 0xAA, BENCH_ZIO_SIZE); /* warm up */

	/* Benchmark parity generation methods */
	for (fn = 0; fn < RAIDZ_GEN_NUM; fn++) {
		bench_parity = fn + 1;
		/* New raidz_map is needed for each generate_p/q/r */
		bench_rm = vdev_raidz_map_alloc(bench_zio, SPA_MINBLOCKSHIFT,
		    BENCH_D_COLS + bench_parity, bench_parity);

		benchmark_raidz_impl(bench_rm, fn, benchmark_gen_impl);

		vdev_raidz_map_free(bench_rm);
	}

	/* Benchmark data reconstruction methods */
	bench_rm = vdev_raidz_map_alloc(bench_zio, SPA_MINBLOCKSHIFT,
	    BENCH_COLS, PARITY_PQR);

	for (fn = 0; fn < RAIDZ_REC_NUM; fn++)
		benchmark_raidz_impl(bench_rm, fn, benchmark_rec_impl);

	vdev_raidz_map_free(bench_rm);

	/* cleanup the bench zio */
	zio_data_buf_free(bench_zio->io_data, BENCH_ZIO_SIZE);
	kmem_free(bench_zio, sizeof (zio_t));

	/* install kstats for all impl */
	raidz_math_kstat = kstat_create("zfs", 0, "vdev_raidz_bench",
		"misc", KSTAT_TYPE_NAMED,
		RAIDZ_IMPL_KSTAT_CNT * (raidz_supp_impl_cnt + 2),
		KSTAT_FLAG_VIRTUAL);

	if (raidz_math_kstat != NULL) {
		raidz_math_kstat->ks_data = raidz_impl_kstats;
		kstat_install(raidz_math_kstat);
	}

	/* Finish initialization */
	zfs_vdev_raidz_impl = user_sel_impl;
	raidz_math_initialized = B_TRUE;
}

void
vdev_raidz_math_fini(void)
{
	raidz_impl_ops_t const *curr_impl;
	int i;

	if (raidz_math_kstat != NULL) {
		kstat_delete(raidz_math_kstat);
		raidz_math_kstat = NULL;
	}

	rw_destroy(&vdev_raidz_impl_lock);

	/* fini impl */
	for (i = 0; i < ARRAY_SIZE(raidz_all_maths); i++) {
		curr_impl = raidz_all_maths[i];

		if (curr_impl->fini)
			curr_impl->fini();
	}
}

static const struct {
	char *name;
	enum vdev_raidz_impl_sel sel;
} math_impl_opts[] = {
#if !defined(_KERNEL)
		{ "cycle", IMPL_CYCLE },
#endif
		{ "fastest", IMPL_FASTEST },
		{ "original", IMPL_ORIGINAL },
		{ "scalar", IMPL_SCALAR }
};

/*
 * Function sets desired raidz implementation.
 *
 * Implementation lock is acquired only if we are called after
 * vdev_raidz_math_init(): by using vdev_raidz_impl_set() API, or by writing to
 * module parameter file. Otherwise, if parameter is specified on module load,
 * we are called before _init() when locks are not yet initialized.
 * Parameter trailing whitespace is stripped to allow usage of commands that
 * can add newline to parameter string.
 *
 * @val		Name of raidz implementation to use
 * @param	Unused.
 */
static int
zfs_vdev_raidz_impl_set(const char *val, struct kernel_param *kp)
{
	int err = -EINVAL;
	char req_name[RAIDZ_IMPL_NAME_MAX];
	boolean_t locked = B_FALSE;
	size_t i;

	/* sanitize input */
	i = strnlen(val, RAIDZ_IMPL_NAME_MAX);
	if (i == 0 || i == RAIDZ_IMPL_NAME_MAX)
		return (err);

	strlcpy(req_name, val, RAIDZ_IMPL_NAME_MAX);
	while (i > 0 && !!isspace(req_name[i-1]))
		i--;
	req_name[i] = '\0';

	/* check if lock is initialized */
	if (raidz_math_initialized) {
		rw_enter(&vdev_raidz_impl_lock, RW_WRITER);
		locked = B_TRUE;
	}

	/* Check mandatory options */
	for (i = 0; i < ARRAY_SIZE(math_impl_opts); i++) {
		if (strcmp(req_name, math_impl_opts[i].name) == 0) {
			user_sel_impl = math_impl_opts[i].sel;
			err = 0;
			break;
		}
	}

	/* check all supported impl if init() was already called */
	if (err != 0 && locked) {
		/* check all supported implementations */
		for (i = 0; i < raidz_supp_impl_cnt; i++) {
			if (strcmp(req_name, raidz_supp_impl[i]->name) == 0) {
				user_sel_impl = i;
				err = 0;
				break;
			}
		}
	}

	if (locked) {
		zfs_vdev_raidz_impl = user_sel_impl;
		rw_exit(&vdev_raidz_impl_lock);
	}

	return (err);
}

int
vdev_raidz_impl_set(const char *val)
{
	ASSERT(raidz_math_initialized);

	return (zfs_vdev_raidz_impl_set(val, NULL));
}

#if defined(_KERNEL) && defined(HAVE_SPL)
static int
zfs_vdev_raidz_impl_get(char *buffer, struct kernel_param *kp)
{
	int i, cnt = 0;
	char *fmt;

	ASSERT(raidz_math_initialized);

	rw_enter(&vdev_raidz_impl_lock, RW_READER);

	/* list mandatory options */
	for (i = 0; i < ARRAY_SIZE(math_impl_opts) - 1; i++) {
		if (math_impl_opts[i].sel == zfs_vdev_raidz_impl)
			fmt = "[%s] ";
		else
			fmt = "%s ";

		cnt += sprintf(buffer + cnt, fmt, math_impl_opts[i].name);
	}

	/* list all supported implementations */
	for (i = 0; i < raidz_supp_impl_cnt; i++) {
		fmt = (i == zfs_vdev_raidz_impl) ? "[%s] " : "%s ";
		cnt += sprintf(buffer + cnt, fmt, raidz_supp_impl[i]->name);
	}

	rw_exit(&vdev_raidz_impl_lock);

	return (cnt);
}

module_param_call(zfs_vdev_raidz_impl, zfs_vdev_raidz_impl_set,
	zfs_vdev_raidz_impl_get, NULL, 0644);
MODULE_PARM_DESC(zfs_vdev_raidz_impl, "Select raidz implementation.");
#endif
