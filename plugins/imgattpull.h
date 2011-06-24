static void *imgattpull_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err);
static ssize_t imgattpull_read(void *object, void *buf, size_t count,
					uint8_t *hi);
static int imgattpull_init(void);
static void imgattpull_exit(void);
