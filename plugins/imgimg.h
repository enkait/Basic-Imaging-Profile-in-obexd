static void *imgimg_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err);

static int imgimg_close(void *object);
static ssize_t imgimg_write(void *object, const void *buf, size_t count);
static int imgimg_init(void);
static void imgimg_exit(void);
