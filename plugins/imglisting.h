struct img_listing {
	int handle;
	char *image;
	time_t ctime;
	time_t mtime;
	struct image_attributes *attr;
};

void img_listing_free(struct img_listing *listing);
struct img_listing *get_listing(GSList *image_list, int handle, int *err);
struct img_listing *get_img_listing(const char *path, int handle, int *err);
