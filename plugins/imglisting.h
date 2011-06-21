static void *imglisting_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err);
static ssize_t imglisting_read(void *object, void *buf, size_t count,
					uint8_t *hi);
static int imglisting_init(void);
static void imglisting_exit(void);
