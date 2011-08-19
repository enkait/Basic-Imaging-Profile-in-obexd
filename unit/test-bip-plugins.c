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

char img_desc_data[] = "<image-descriptor version=\"1.0\">\n"
	"<image encoding=\"JPEG2000\" pixel=\"10**-1280*960\" maxsize=\"500000\"/>\n"
	"</image-descriptor>";
struct img_desc img_desc = { "JP2", { 1280, 960 }, { 1280, 960 }, FALSE, 
				500000, NULL };
char img_desc_data_empty[] = "<image-descriptor version=\"1.0\">\n"
	"<image encoding=\"\" pixel=\"\" transformation=\"stretch\"/>\n"
	"</image-descriptor>";
struct img_desc img_desc_empty = { "JP2", { 1280, 960 }, { 1280, 960 }, FALSE, 
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

static void test_parse_img_desc(void)
{
	int err;
	struct img_desc *d = parse_img_desc(img_desc_data,
						sizeof(img_desc_data), &err);
	g_assert(d != NULL);
	assert_memequal(&img_desc, sizeof(struct img_desc),
					d, sizeof(struct img_desc));
}

int main(int argc, char *argv[])
{
	printf("wut");
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/bip/parse_img_desc", test_parse_img_desc);

	g_test_run();

	return 0;
}
