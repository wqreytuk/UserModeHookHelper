#pragma once

// Provide a user-mode implementation when building user-mode.
// Kernel-only declaration
#include "../include/umhh_ioctl.h"
BOOLEAN BS_SendSuspendInjectQueue(BOOLEAN suspend);
