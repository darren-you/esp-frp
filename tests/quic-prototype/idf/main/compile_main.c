// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
extern int efrp_quic_prototype_run(int argc, char **argv);
static int (*volatile prototype_entry)(int, char **) = efrp_quic_prototype_run;
void app_main(void)
{
    /* Keep the full client and adapter linked without invoking its host-only
       fixture runner or pretending a network/hardware acceptance occurred. */
    puts(prototype_entry ? "QUIC prototype compile proof ready" : "QUIC prototype entry missing");
}
