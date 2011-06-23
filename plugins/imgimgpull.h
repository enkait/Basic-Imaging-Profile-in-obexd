static void *imgimgpull_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err);
static ssize_t imgimgpull_read(void *object, void *buf, size_t count,
					uint8_t *hi);
static int imgimgpull_init(void);
static void imgimgpull_exit(void);
