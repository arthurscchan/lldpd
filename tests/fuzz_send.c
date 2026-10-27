/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2026 Arthr SC Chan <arthur.chan@adalogics.com>
 *
 * Decode/encode round-trip: the fuzzed frame is first decoded by
 * lldp_decode() into a chassis/port pair, then re-encoded through the
 * real send paths (lldp_send/cdp_send/edp_send/sonmp_send) with a sink
 * transmit op — covering the whole encode direction of the protocol
 * implementations on attacker-shaped structures.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "../src/daemon/lldpd.h"

#include <string.h>

#define kMinInputLength 5
#define kMaxInputLength 2048

/* Use this callback to avoid some logs */
void donothing(int pri, const char *msg) { };

static int
sink_send(struct lldpd *cfg, struct lldpd_hardware *hardware, char *buffer,
    size_t size)
{
	(void)cfg; (void)hardware; (void)buffer;
	return size;
}

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	struct lldpd global;
	struct lldpd_hardware hardware;
	struct lldpd_hardware fake;
	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;
	static struct lldpd_ops ops = { .send = sink_send };

	if (Size < kMinInputLength || Size > kMaxInputLength) {
		return 0;
	}

	log_register(donothing);

	memset(&global, 0, sizeof(global));
	memset(&hardware, 0, sizeof(hardware));
	memset(&fake, 0, sizeof(fake));

	hardware.h_ops = &ops;
	strlcpy(hardware.h_ifname, "fuzz0", sizeof(hardware.h_ifname));
	hardware.h_mtu = 512 + (Data[0] << 5) % 8000;
	hardware.h_mangle = Data[1] & 1;

	lldp_decode(NULL, (char *)Data, Size, &fake, &nchassis, &nport);
	if (!nchassis || !nport) {
		return 0;
	}

	/* Encode what was just decoded: the port carries the decoded TLVs. */
	if (nport->p_chassis == NULL)
		nport->p_chassis = nchassis;
	hardware.h_lport = *nport;

	lldp_send(&global, &hardware);
#ifdef ENABLE_CDP
	cdpv1_send(&global, &hardware);
	cdpv2_send(&global, &hardware);
#endif
#ifdef ENABLE_FDP
	fdp_send(&global, &hardware);
#endif
#ifdef ENABLE_EDP
	edp_send(&global, &hardware);
#endif
#ifdef ENABLE_SONMP
	sonmp_send(&global, &hardware);
#endif

	/* The send paths cache the last frame inside the port copy. */
	free(hardware.h_lport.p_lastframe);

	lldpd_port_cleanup(nport, 1);
	free(nport);
	lldpd_chassis_cleanup(nchassis, 1);

	return 0;
}
