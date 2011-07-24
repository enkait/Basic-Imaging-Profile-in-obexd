void *img_capabilities_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err);
ssize_t img_capabilities_read(void *object, void *buf, size_t count);
ssize_t imgimg_write(void *object, const void *buf, size_t count);
int imgimg_close(void *object);
