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

struct image_attributes *get_image_attributes(const char *image_file, int *err);
void free_image_attributes(struct image_attributes *attr);
int make_modified_image(const char *image_path, const char *modified_path,
			struct image_attributes *attr, const char *transform,
			int *err);

const gchar *convBIP2IM(const gchar *encoding);
const gchar *convIM2BIP(const gchar *encoding);
gboolean verify_transform(const char *transform);
time_t parse_iso8601_bip(const gchar *str, int len);
gboolean parse_pixel_range(const gchar *dim, unsigned int *lower,
				unsigned int *upper, gboolean *fixed_ratio);
gboolean make_thumbnail(const char *image_path, const char *modified_path,
								int *err);
int parse_handle(const char *data);
char *parse_transform(const char *transform);
char *parse_transform_list(const char *transform);
gboolean verify_unsignednumber(const char *size);
char *parse_unsignednumber(const char *size);

void parse_bip_user_headers(const struct obex_session *os, obex_object_t *obj,
				char **desc_hdr,
				unsigned int *desc_hdr_len,
				char **handle_hdr,
				unsigned int *handle_hdr_len);

char *get_att_dir(const char *image_path);
char *safe_rename(const char *name, const char *folder, const char *orig_path,
								int *err);
char *insert_number(const char *path, unsigned int number);

struct a_header *create_handle(const char *handle);
ssize_t add_reply_handle(void *buf, size_t mtu, uint8_t *hi, int handle);
char *get_null_terminated(char *buffer, int len);
