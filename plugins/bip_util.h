struct image_attributes {
    char * format;
    size_t width, height;
    unsigned long length;
};

guint8 *encode_img_descriptor(const gchar *data, unsigned int length, unsigned int *newsize);
guint8 *decode_img_descriptor(const gchar *data, unsigned int length, unsigned int *newsize);
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
