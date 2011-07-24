#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "obex-xfer.h"
#include "obex-priv.h"
#include "wand/MagickWand.h"
#include "bip_pull.h"
#include "bip_push.h"
#include "bip_rd.h"
#include "bip_util.h"
#include "bip_arch.h"

GDBusMethodTable remote_display_methods[] = {
	{ "PutImage", "s", "", put_image },
	{ "PutModifiedImage", "ssuus", "", put_modified_image },
	{ "GetImagesListing",	"a{sv}", "aa{ss}", get_images_listing,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

GDBusSignalTable remote_display_signals[] = {
	{ }
};
