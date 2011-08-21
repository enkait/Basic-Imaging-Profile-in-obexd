struct imgattpush_data {
	int fd;
	struct image_push_session *context;
	char *path, *att_path, *name;
	int handle;
};

void free_imgattpush_data(struct imgattpush_data *data);

static void *imgattpush_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err);

static int imgattpush_close(void *object);
static ssize_t imgattpush_write(void *object, const void *buf, size_t count);
static int imgattpush_init(void);
static void imgattpush_exit(void);
