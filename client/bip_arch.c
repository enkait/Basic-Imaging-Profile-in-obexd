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
#include "bip_util.h"
#include "bip_arch.h"

static struct sa_aparam *create_sa_aparam(const char *serviceid) {
	struct sa_aparam *sa = g_new0(struct sa_aparam, 1);
	sa->sidtag = SID_TAG;
	sa->sidlen = SID_LEN;
	g_memmove(sa->sid, serviceid, SID_LEN);
	return sa;
}

static DBusMessage *start_archive(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply;
	char *handle;
	struct sa_aparam *aparam;
	GSList *aheaders;
	int err;

	printf("requested start archive\n");
	
	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &handle,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	aparam = create_sa_aparam(AOS_SID);

	if (!gw_obex_put_buf_with_aheaders(session->obex, NULL,
						"x-bt/img-archive",
						(uint8_t *) aparam,
						sizeof(struct sa_aparam),
						NULL, NULL, 0, -1, &err)) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"334Failed");
	}

	if (session->obex && session->obex->xfer && session->obex->xfer->aheaders) {
		aheaders = session->obex->xfer->aheaders;
		while (aheaders != NULL) {
			struct a_header *ah = aheaders->data;
			printf("%d\n", ah->hi);
			aheaders = g_slist_next(aheaders);
		}
	}
	
	reply = dbus_message_new_method_return(message);
	return reply;
}


GDBusMethodTable archive_methods[] = {
	{ "StartArchive", "", "", start_archive },
	{ }
};

GDBusSignalTable archive_signals[] = {
	{ }
};
