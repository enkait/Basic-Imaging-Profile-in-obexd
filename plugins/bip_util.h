#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define __USE_XOPEN
#include <time.h>

#include <glib.h>
#include <regex.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

struct image_attributes {
    char * format;
    size_t width, height;
    unsigned long length;
};

uint8_t *encode_img_handle(const char *data, unsigned int length, unsigned int *newsize);
char *decode_img_handle(const uint8_t *data, unsigned int length, unsigned int *newsize);
uint8_t *encode_img_descriptor(const char *data, unsigned int length, unsigned int *newsize);
char *decode_img_descriptor(const uint8_t *data, unsigned int length, unsigned int *newsize);

const gchar *convert_encoding_BIP_to_IM(const gchar *encoding);
const gchar *convert_encoding_IM_to_BIP(const gchar *encoding);
int get_image_attributes(const char * image_file, struct image_attributes * attr);
void free_image_attributes(struct image_attributes *attr);

/** Convert a time string in ISO8601 format to time_t
 * @param str Time string in ISO8601 format
 * @param len Length of string
 * @returns time as time_t format
 */
time_t parse_iso8601(const gchar *str, int len);
gboolean parse_pixel_range(const gchar *dim, unsigned int *lower, unsigned int *upper, gboolean *fixed_ratio);
int make_modified_image(const char *image_path, const char *modified_path,
			struct image_attributes *attr, const char *transform);
