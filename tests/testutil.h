/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef TESTUTIL_H
# define TESTUTIL_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>

static int tu_count = 0;
static int tu_pass = 0;

# define TEST(name) static void name(void)

# define ASSERT(expr) do {							\
    if (!(expr)) {								\
        fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);	\
        exit(1);								\
    }										\
} while (0)

# define ASSERT_EQ(a, b)         ASSERT((a) == (b))
# define ASSERT_NEQ(a, b)        ASSERT((a) != (b))
# define ASSERT_NULL(p)          ASSERT((p) == NULL)
# define ASSERT_NOT_NULL(p)      ASSERT((p) != NULL)
# define ASSERT_STR_EQ(a, b)     ASSERT(strcmp((a), (b)) == 0)
# define ASSERT_MEM_EQ(a, b, n)  ASSERT(memcmp((a), (b), (n)) == 0)

# define RUN(name) do {		\
    printf("  " #name " ... ");	\
    fflush(stdout);		\
    name();			\
    tu_pass++;			\
    tu_count++;			\
    printf("ok\n");		\
} while (0)

# define TEST_MAIN_BEGIN(suite)	\
    int main(void) { printf(suite ":\n");

# define TEST_MAIN_END \
    printf("%d/%d passed\n", tu_pass, tu_count); \
    return (tu_pass == tu_count) ? 0 : 1; }

#endif
