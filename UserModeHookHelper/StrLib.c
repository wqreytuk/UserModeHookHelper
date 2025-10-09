#include "StrLib.h"

BOOLEAN SL_EqualWideString(WCHAR* a1, WCHAR* a2, BOOLEAN ignoreCase) {
	// Treat NULL pointers as unequal to any non-NULL string. If both are NULL,
	// consider them equal.
	if (a1 == NULL && a2 == NULL) return TRUE;
	if (a1 == NULL || a2 == NULL) return FALSE;

	UNICODE_STRING uniA1;
	UNICODE_STRING uniA2;
	RtlInitUnicodeString(&uniA1, a1);
	RtlInitUnicodeString(&uniA2, a2);
	return RtlEqualUnicodeString(&uniA1, &uniA2, ignoreCase);
}