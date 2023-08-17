pub struct HmacSession {}

pub struct PolicySession {}

pub enum SessionState {
    Hmac(HmacSession),
    Policy(PolicySession),
}

pub struct Session {
    pub state: SessionState
}
