static void *imgpropull_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err);
static ssize_t imgpropull_read(void *object, void *buf, size_t count,
					uint8_t *hi);
static int imgpropull_init(void);
static void imgpropull_exit(void);
