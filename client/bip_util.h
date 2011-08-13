#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

#define THUMBNAIL_WIDTH 160
#define THUMBNAIL_HEIGHT 120

struct image_attributes {
    char *encoding;
    size_t width, height;
    unsigned long length;
};

struct encconv_pair {
	gchar *bip, *im;
};

extern struct encconv_pair encconv_table[];

uint8_t *encode_img_handle(const char *data, unsigned int length,
						unsigned int *newsize);
char *decode_img_handle(const uint8_t *data, unsigned int length,
						unsigned int *newsize);
uint8_t *encode_img_descriptor(const char *data, unsigned int length,
						unsigned int *newsize);
char *decode_img_descriptor(const uint8_t *data, unsigned int length,
						unsigned int *newsize);

const gchar *convBIP2IM(const gchar *encoding);
const gchar *convIM2BIP(const gchar *encoding);
gboolean verify_transform(const char *transform);
struct image_attributes *get_image_attributes(const char *image_file, int *err);
void free_image_attributes(struct image_attributes *attr);

/** Convert a time string in ISO8601 format to time_t
 * @param str Time string in ISO8601 format
 * @param len Length of string
 * @returns time as time_t format
 */
time_t parse_iso8601_bip(const gchar *str, int len);
gboolean parse_pixel_range(const gchar *dim, unsigned int *lower,
				unsigned int *upper, gboolean *fixed_ratio);
int make_modified_image(const char *image_path, const char *modified_path,
			struct image_attributes *attr, const char *transform,
			int *err);
gboolean make_thumbnail(const char *image_path, const char *modified_path,
								int *err);
int parse_handle(const char *data);
//gboolean parse_bip_header(char **header, unsigned int *hdr_len,
//			uint8_t hi, const uint8_t *data, unsigned int hlen);
void parse_bip_user_headers(const struct obex_session *os, obex_object_t *obj,
				char **desc_hdr,
				unsigned int *desc_hdr_len,
				char **handle_hdr,
				unsigned int *handle_hdr_len);
char *parse_transform(const char *transform);
char *parse_transform_list(const char *transform);
char *parse_unsignednumber(const char *size);
char *get_att_dir(const char *image_path);
char *safe_rename(const char *name, const char *folder,
							const char *orig_path);
struct a_header *create_handle(const char *handle);
char *get_null_terminated(char *buffer, int len);
void parse_client_user_headers(const GSList *aheaders,
				char **desc_hdr,
				unsigned int *desc_hdr_len,
				char **handle_hdr,
				unsigned int *handle_hdr_len);
