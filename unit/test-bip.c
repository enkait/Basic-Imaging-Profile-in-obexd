/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

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
#include <client/bip_util.h>

#include "util.h"

static uint8_t enc_handle[] = { 0x00, '0', 0x00, '1', 0x00, '2',
				0x00, '3', 0x00, '4', 0x00, '5',
				0x00, '6', 0x00, 0x00 };
static char dec_handle[] = "0123456";

static void test_dec_img_handle(void)
{
	unsigned int size = 0;
	char *data = decode_img_handle(enc_handle, sizeof(enc_handle), &size);
	assert_memequal(dec_handle, sizeof(dec_handle), data, size+1);

	g_free(data);
}

static void test_dec_img_handle_null(void)
{
	unsigned int size = 0;
	char *data = decode_img_handle(NULL, 0, &size);
	g_assert_cmpint(size, ==, 0);
	g_assert_cmpint(data[0], ==, '\0');
	g_free(data);
}

static void test_enc_img_handle(void)
{
	unsigned int size = 0;
	uint8_t *data = encode_img_handle(dec_handle, sizeof(dec_handle)-1, &size);
	assert_memequal(enc_handle, sizeof(enc_handle), data, size);

	g_free(data);
}

static void test_enc_img_handle_null(void)
{
	unsigned int size = 0;
	uint8_t *data = encode_img_handle(NULL, 0, &size);
	g_assert_cmpint(size, ==, 0);
	g_assert(data == NULL);
}

struct pixel_range_test {
	char *range;
	unsigned int lower_ret[2], upper_ret[2];
	gboolean fixed, ret;
	char *message;
};

struct pixel_range_test pixel_range_tests[] = {
	{ "1232*21223", { 1232, 21223 }, { 1232, 21223 }, FALSE, TRUE,
						"Failed fixed pixel size" },
	{ "10*20-10*30", { 10, 20 }, { 10, 30 }, FALSE, TRUE,
						"Failed pixel range" },
	{ "10**-10*30", { 10, 0 }, { 10, 30 }, TRUE, TRUE,
						"Failed fixed aspect ratio" },
	{ "0*0-65535*65535", { 0, 0 }, { 65535, 65535 }, FALSE, TRUE,
						"Failed max range" },
	{ "0*12313-300*12000", { }, { }, FALSE, FALSE,
						"Failed illegal range" },
	{ "0*-", { }, { }, FALSE, FALSE, "Failed gibberish" },
	{ "65536*65536", { }, { }, FALSE, FALSE, "Failed size too large" },
	{ "100*-10*300" , { }, { }, FALSE, FALSE, "Failed illegal range" },
	{ }
};

static void test_parse_pixel_range(void)
{
	struct pixel_range_test *data;
	unsigned int lower_ret[2], upper_ret[2];
	gboolean fixed;
	int i;
	for (data = pixel_range_tests; data && data->range; data++) {
		gboolean ret = parse_pixel_range(data->range, lower_ret,
						upper_ret, &fixed);
		g_assert((ret == FALSE) == (data->ret == FALSE));
		if (!ret)
			continue;
		for (i = 0; i < 2; i++)
			g_assert_cmpuint(lower_ret[i], ==, data->lower_ret[i]);
		for (i = 0; i < 2; i++)
			g_assert_cmpuint(upper_ret[i], ==, data->upper_ret[i]);
		g_assert((fixed == FALSE) == (data->fixed == FALSE));
	}
}

static void test_parse_handle(void)
{
	static char handle_data[] = "2321231";
	static int handle = 2321231;
	g_assert(parse_handle(handle_data) == handle);
}

static void test_parse_handle_empty(void)
{
	static char handle_data[] = "";
	g_assert(parse_handle(handle_data) == -1);
}

static void test_parse_handle_null(void)
{
	g_assert(parse_handle(NULL) == -1);
}

static void test_parse_handle_short(void)
{
	static char handle_data[] = "123123";
	g_assert(parse_handle(handle_data) == -1);
}

static void test_parse_handle_long(void)
{
	static char handle_data[] = "12323123";
	g_assert(parse_handle(handle_data) == -1);
}

static void test_parse_handle_illegal(void)
{
	static char handle_data[] = "123a123";
	g_assert(parse_handle(handle_data) == -1);
}

static void test_parse_transform_legal(void)
{
	char *result = parse_transform("stretch");
	g_assert_cmpstr(result, ==, "stretch");
	g_free(result);
	result = parse_transform("crop");
	g_assert_cmpstr(result, ==, "crop");
	g_free(result);
	result = parse_transform("fill");
	g_assert_cmpstr(result, ==, "fill");
	g_free(result);
}

static void test_parse_transform_trailing_space(void)
{
	char *result = parse_transform("stretch ");
	g_assert(result == NULL);
}

static void test_parse_transform_list(void)
{
	char *result = parse_transform_list("stretch crop fill");
	g_assert_cmpstr(result, ==, "stretch crop fill");
	g_free(result);
}

static void test_parse_transform_list_trailing_space(void)
{
	char *result = parse_transform_list("stretch crop fill ");
	g_assert(result == NULL);
}

static void test_parse_transform_list_repetition(void)
{
	char *result1 = parse_transform_list("stretch crop fill stretch");
	char *result2 = parse_transform_list("stretch crop fill crop");
	char *result3 = parse_transform_list("stretch crop fill fill");
	g_assert(result1 == NULL && result2 == NULL && result3 == NULL);
}

static void test_parse_unsignednumber(void)
{
	char number[] = "123123123131";
	char *result = parse_unsignednumber(number);
	g_assert_cmpstr(number, ==, result);
}

static void test_parse_unsignednumber_illegal(void)
{
	char number[] = "123123a23131";
	char *result = parse_unsignednumber(number);
	g_assert(result == NULL);
}

static void test_parse_unsignednumber_empty(void)
{
	char number[] = "";
	char *result = parse_unsignednumber(number);
	g_assert(result == NULL);
}

static void test_insert_number(void)
{
	char filename[] = "foo.tar.gz";
	char *res = insert_number(filename, 14);
	g_assert_cmpstr("foo_14.tar.gz", ==, res);
}

static void test_insert_number_no_ext(void)
{
	char filename[] = "foo";
	char *res = insert_number(filename, 0);
	printf("%s\n", res);
	g_assert_cmpstr("foo_0", ==, res);
}

static void test_insert_number_disadv(void)
{
	char filename[] = "this.is.not.extension.tar.gz";
	char *res = insert_number(filename, 123);
	g_assert_cmpstr("this_123.is.not.extension.tar.gz", ==, res);
}

static void test_get_null_terminated_no_change(void)
{
	char data[] = "123123abc";
	char *res = get_null_terminated(data, sizeof(data));
	g_assert_cmpstr(data, ==, res);
}

static void test_get_null_terminated_null(void)
{
	char *res = get_null_terminated(NULL, 0);
	g_assert_cmpstr("", ==, res);
}

static void test_get_null_terminated(void)
{
	char data[] = { 'a', 'b', 'c' };
	char *res = get_null_terminated(data, sizeof(data));
	g_assert_cmpstr("abc", ==, res);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/bip/decode_img_handle", test_dec_img_handle);
	g_test_add_func("/bip/decode_img_handle_null",
				test_dec_img_handle_null);
	g_test_add_func("/bip/encode_img_handle", test_enc_img_handle);
	//g_test_add_func("/bip/encode_img_handle_null", test_dec_img_handle_null);
	g_test_add_func("/bip/encode_img_handle_null",
				test_enc_img_handle_null);
	g_test_add_func("/bip/parse_pixel_range", test_parse_pixel_range);
	g_test_add_func("/bip/parse_handle/good", test_parse_handle);
	g_test_add_func("/bip/parse_handle/null", test_parse_handle_null);
	g_test_add_func("/bip/parse_handle/empty", test_parse_handle_empty);
	g_test_add_func("/bip/parse_handle/short", test_parse_handle_short);
	g_test_add_func("/bip/parse_handle/long", test_parse_handle_long);
	g_test_add_func("/bip/parse_handle/illegal",
				test_parse_handle_illegal);
	g_test_add_func("/bip/parse_transform/legal",
				test_parse_transform_legal);
	g_test_add_func("/bip/parse_transform/trailing_space",
				test_parse_transform_trailing_space);
	g_test_add_func("/bip/parse_transform_list/legal",
				test_parse_transform_list);
	g_test_add_func("/bip/parse_transform_list/trailing_space",
				test_parse_transform_list_trailing_space);
	g_test_add_func("/bip/parse_transform_list/repetition",
				test_parse_transform_list_repetition);
	g_test_add_func("/bip/parse_unsignednumber",
				test_parse_unsignednumber);
	g_test_add_func("/bip/parse_unsignednumber_illegal",
				test_parse_unsignednumber_illegal);
	g_test_add_func("/bip/parse_unsignednumber_empty",
				test_parse_unsignednumber_empty);
	g_test_add_func("/bip/insert_number/many_ext",
				test_insert_number);
	g_test_add_func("/bip/insert_number/no_ext",
				test_insert_number_no_ext);
	g_test_add_func("/bip/insert_number/disadv",
				test_insert_number_disadv);
	g_test_add_func("/bip/get_null_terminated/no_change",
				test_get_null_terminated_no_change);
	g_test_add_func("/bip/get_null_terminated/not_terminated",
				test_get_null_terminated);
	g_test_add_func("/bip/get_null_terminated/null",
				test_get_null_terminated_null);

	g_test_run();

	return 0;
}
