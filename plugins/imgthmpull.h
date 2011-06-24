static void *imgthmpull_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err);
static ssize_t imgthmpull_read(void *object, void *buf, size_t count,
					uint8_t *hi);
static int imgthmpull_init(void);
static void imgthmpull_exit(void);
