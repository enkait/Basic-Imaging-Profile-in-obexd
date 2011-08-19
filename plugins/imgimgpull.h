struct img_desc {
	char *encoding;
	unsigned int lower[2], upper[2];
	gboolean fixed_ratio;
	unsigned int maxsize;
	char *transform;
};

gboolean img_elem_attr(struct img_desc *desc, const gchar *key,
					const gchar *value, GError **gerr);
void img_elem(GMarkupParseContext *ctxt, const gchar *element,
			const gchar **names, const gchar **values,
			gpointer user_data, GError **gerr);
struct img_desc *parse_img_desc(char *data, unsigned int length,
								int *err);
struct image_attributes *new_image_attr(struct image_attributes *orig,
					struct img_desc *desc);
