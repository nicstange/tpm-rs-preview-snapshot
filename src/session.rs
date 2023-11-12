// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

pub struct HmacSession {}

pub struct PolicySession {}

pub enum SessionState {
    Hmac(HmacSession),
    Policy(PolicySession),
}

pub struct Session {
    pub state: SessionState
}
