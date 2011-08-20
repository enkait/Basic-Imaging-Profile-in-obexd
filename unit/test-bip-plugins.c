#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <glib.h>
#include <regex.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>
#include <wand/MagickWand.h>

#include "obex-xfer.h"
#include "obex-priv.h"
#include <plugins/imgimgpull.h>

#include "util.h"

static gboolean cmp_img_desc(const struct img_desc *a, const struct img_desc *b)
{
	int i;
	if (g_strcmp0(a->encoding, b->encoding) != 0)
		return FALSE;
	for (i = 0; i < 2; i++)
		if (a->lower[i] != b->lower[i])
			return FALSE;
	for (i = 0; i < 2; i++)
		if (a->upper[i] != b->upper[i])
			return FALSE;
	if (a->maxsize != b->maxsize)
		return FALSE;
	if (a->fixed_ratio != b->fixed_ratio)
		return FALSE;
	if (g_strcmp0(a->transform, b->transform) != 0)
		return FALSE;
	return TRUE;
}

char img_desc_data_ok[] = "<image-descriptor version=\"1.0\">\n"
	"<image encoding=\"JPEG2000\" pixel=\"10**-1280*960\" maxsize=\"500000\"/>\n"
	"</image-descriptor>";
struct img_desc img_desc_ok = { "JP2", { 10, 0 }, { 1280, 960 }, TRUE, 
				500000, NULL };
char img_desc_data_empty[] = "<image-descriptor version=\"1.0\">\n"
	"<image encoding=\"\" pixel=\"\" transformation=\"stretch\"/>\n"
	"</image-descriptor>";
struct img_desc img_desc_empty = { NULL, { 0, 0 }, { UINT_MAX, UINT_MAX }, FALSE, 
				UINT_MAX, "stretch" };
char img_desc_data_noenc[] = "<image-descriptor version=\"1.0\">\n"
	"<image pixel=\"\" transformation=\"stretch\"/>\n"
	"</image-descriptor>";
char img_desc_data_nopix[] = "<image-descriptor version=\"1.0\">\n"
	"<image encoding=\"\" transformation=\"stretch\"/>\n"
	"</image-descriptor>";
char img_desc_data_multi[] = "<image-descriptor version=\"1.0\">\n"
	"<image encoding=\"\" pixel=\"\" transformation=\"stretch\"/>\n"
	"<image encoding=\"\" pixel=\"\" transformation=\"stretch\"/>\n"
	"</image-descriptor>";

static void test_parse_img_desc_ok(void)
{
	int err;
	struct img_desc *d = parse_img_desc(img_desc_data_ok,
						sizeof(img_desc_data_ok)-1, &err);
	g_assert(d != NULL);
	g_assert(cmp_img_desc(&img_desc_ok, d));
}

static void test_parse_img_desc_empty(void)
{
	int err;
	struct img_desc *d = parse_img_desc(img_desc_data_empty,
						sizeof(img_desc_data_empty)-1, &err);
	g_assert(d != NULL);
	g_assert(cmp_img_desc(&img_desc_empty, d));
}

static void test_parse_img_desc_noenc(void)
{
	int err;
	struct img_desc *d = parse_img_desc(img_desc_data_noenc,
						sizeof(img_desc_data_noenc)-1, &err);
	g_assert(d == NULL);
	g_assert_cmpint(err, ==, -EINVAL);
}

static void test_parse_img_desc_nopix(void)
{
	int err;
	struct img_desc *d = parse_img_desc(img_desc_data_noenc,
						sizeof(img_desc_data_noenc)-1, &err);
	g_assert(d == NULL);
	g_assert_cmpint(err, ==, -EINVAL);
}

static void test_parse_img_desc_multi(void)
{
	int err;
	struct img_desc *d = parse_img_desc(img_desc_data_multi,
						sizeof(img_desc_data_multi)-1, &err);
	g_assert(d == NULL);
	g_assert_cmpint(err, ==, -EINVAL);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/bip/parse_img_desc/ok", test_parse_img_desc_ok);
	g_test_add_func("/bip/parse_img_desc/empty", test_parse_img_desc_empty);
	g_test_add_func("/bip/parse_img_desc/noenc", test_parse_img_desc_noenc);
	g_test_add_func("/bip/parse_img_desc/nopix", test_parse_img_desc_nopix);
	g_test_add_func("/bip/parse_img_desc/multi", test_parse_img_desc_multi);

	g_test_run();

	return 0;
}
