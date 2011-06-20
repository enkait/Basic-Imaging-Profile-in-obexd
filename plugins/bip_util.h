struct image_attributes {
    char * format;
    size_t width, height;
    unsigned long length;
};

guint8 *encode_img_descriptor(const gchar *data, unsigned int length, unsigned int *newsize);
const gchar *convert_encoding_BIP_to_IM(const gchar *encoding);
const gchar *convert_encoding_IM_to_BIP(const gchar *encoding);
int get_image_attributes(const char * image_file, struct image_attributes * attr);
void free_image_attributes(struct image_attributes *attr);
