//! IKEv2 state machine
//!
//! Implements the IKE SA state transitions as defined in RFC 7296.
//!
//! # State Transitions
//!
//! ```text
//! IDLE
//!   ↓ (send IKE_SA_INIT request)
//! INIT_SENT
//!   ↓ (recv IKE_SA_INIT response)
//! INIT_DONE
//!   ↓ (send IKE_AUTH request)
//! AUTH_SENT
//!   ↓ (recv IKE_AUTH response)
//! ESTABLISHED
//!   ↓ (handle CREATE_CHILD_SA, INFORMATIONAL)
//! REKEYING / DELETING
//! ```

use crate::ipsec::{Error, Result};

/// IKE SA state
///
/// Represents the current state of an IKE Security Association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeState {
    /// Initial state - no exchange started
    Idle,

    /// IKE_SA_INIT request sent, waiting for response
    InitSent,

    /// IKE_SA_INIT completed, ready for IKE_AUTH
    InitDone,

    /// IKE_AUTH request sent, waiting for response
    AuthSent,

    /// IKE SA established, ready for Child SA creation
    Established,

    /// Rekeying in progress
    Rekeying,

    /// Deletion in progress
    Deleting,

    /// IKE SA deleted
    Deleted,
}

impl IkeState {
    /// Check if state is a valid next state
    pub fn can_transition_to(&self, next: IkeState) -> bool {
        use IkeState::*;

        match (self, next) {
            // Forward transitions (Initiator)
            (Idle, InitSent) => true,
            (InitSent, InitDone) => true,
            (InitDone, AuthSent) => true,
            (AuthSent, Established) => true,

            // Forward transitions (Responder)
            (Idle, InitDone) => true, // Responder receives IKE_SA_INIT
            (InitDone, Established) => true, // Responder receives IKE_AUTH

            // Rekeying
            (Established, Rekeying) => true,
            (Rekeying, Established) => true,

            // Deletion from any state
            (_, Deleting) => true,
            (Deleting, Deleted) => true,

            // Stay in same state (retransmission, etc.)
            (s1, s2) if *s1 == s2 => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, IkeState::Deleted)
    }

    /// Check if IKE SA is established
    pub fn is_established(&self) -> bool {
        matches!(self, IkeState::Established | IkeState::Rekeying)
    }

    /// Check if waiting for response
    pub fn is_waiting(&self) -> bool {
        matches!(self, IkeState::InitSent | IkeState::AuthSent)
    }
}

/// IKE SA state machine
///
/// Manages state transitions and validates state changes.
#[derive(Debug, Clone)]
pub struct IkeStateMachine {
    /// Current state
    state: IkeState,

    /// Is this the initiator?
    is_initiator: bool,

    /// Message ID for next request (initiator only)
    next_message_id: u32,

    /// Expected response message ID (waiting states)
    expected_response_id: Option<u32>,
}

impl IkeStateMachine {
    /// Create new state machine for initiator
    pub fn new_initiator() -> Self {
        IkeStateMachine {
            state: IkeState::Idle,
            is_initiator: true,
            next_message_id: 0,
            expected_response_id: None,
        }
    }

    /// Create new state machine for responder
    pub fn new_responder() -> Self {
        IkeStateMachine {
            state: IkeState::Idle,
            is_initiator: false,
            next_message_id: 0,
            expected_response_id: None,
        }
    }

    /// Get current state
    pub fn state(&self) -> IkeState {
        self.state
    }

    /// Check if this is the initiator
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Get next message ID for sending
    pub fn next_message_id(&self) -> u32 {
        self.next_message_id
    }

    /// Transition to a new state
    ///
    /// # Errors
    ///
    /// Returns error if transition is invalid
    pub fn transition(&mut self, new_state: IkeState) -> Result<()> {
        if !self.state.can_transition_to(new_state) {
            return Err(Error::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: format!("{:?}", new_state),
            });
        }

        self.state = new_state;
        Ok(())
    }

    /// Handle sending IKE_SA_INIT request (initiator)
    pub fn send_init_request(&mut self) -> Result<u32> {
        if !self.is_initiator {
            return Err(Error::InvalidState(
                "Only initiator can send IKE_SA_INIT request".to_string(),
            ));
        }

        self.transition(IkeState::InitSent)?;

        let msg_id = self.next_message_id;
        self.expected_response_id = Some(msg_id);
        self.next_message_id += 1;

        Ok(msg_id)
    }

    /// Handle receiving IKE_SA_INIT request (responder)
    pub fn recv_init_request(&mut self, message_id: u32) -> Result<()> {
        if self.is_initiator {
            return Err(Error::InvalidState(
                "Initiator cannot receive IKE_SA_INIT request".to_string(),
            ));
        }

        if self.state != IkeState::Idle {
            return Err(Error::InvalidState(format!(
                "Cannot receive IKE_SA_INIT in state {:?}",
                self.state
            )));
        }

        // Responder expects message ID 0 for initial exchange
        if message_id != 0 {
            return Err(Error::InvalidMessage(format!(
                "Expected message ID 0, got {}",
                message_id
            )));
        }

        self.transition(IkeState::InitDone)?;
        Ok(())
    }

    /// Handle receiving IKE_SA_INIT response (initiator)
    pub fn recv_init_response(&mut self, message_id: u32) -> Result<()> {
        if !self.is_initiator {
            return Err(Error::InvalidState(
                "Responder cannot receive IKE_SA_INIT response".to_string(),
            ));
        }

        if self.state != IkeState::InitSent {
            return Err(Error::InvalidState(format!(
                "Cannot receive IKE_SA_INIT response in state {:?}",
                self.state
            )));
        }

        // Validate message ID matches expected
        if Some(message_id) != self.expected_response_id {
            return Err(Error::InvalidMessage(format!(
                "Expected message ID {:?}, got {}",
                self.expected_response_id, message_id
            )));
        }

        self.transition(IkeState::InitDone)?;
        self.expected_response_id = None;
        Ok(())
    }

    /// Handle sending IKE_AUTH request (initiator)
    pub fn send_auth_request(&mut self) -> Result<u32> {
        if !self.is_initiator {
            return Err(Error::InvalidState(
                "Only initiator can send IKE_AUTH request".to_string(),
            ));
        }

        if self.state != IkeState::InitDone {
            return Err(Error::InvalidState(format!(
                "Cannot send IKE_AUTH from state {:?}",
                self.state
            )));
        }

        self.transition(IkeState::AuthSent)?;

        let msg_id = self.next_message_id;
        self.expected_response_id = Some(msg_id);
        self.next_message_id += 1;

        Ok(msg_id)
    }

    /// Handle receiving IKE_AUTH request (responder)
    pub fn recv_auth_request(&mut self, message_id: u32) -> Result<()> {
        if self.is_initiator {
            return Err(Error::InvalidState(
                "Initiator cannot receive IKE_AUTH request".to_string(),
            ));
        }

        if self.state != IkeState::InitDone {
            return Err(Error::InvalidState(format!(
                "Cannot receive IKE_AUTH in state {:?}",
                self.state
            )));
        }

        // IKE_AUTH should have message ID 1
        if message_id != 1 {
            return Err(Error::InvalidMessage(format!(
                "Expected message ID 1, got {}",
                message_id
            )));
        }

        self.transition(IkeState::Established)?;
        Ok(())
    }

    /// Handle receiving IKE_AUTH response (initiator)
    pub fn recv_auth_response(&mut self, message_id: u32) -> Result<()> {
        if !self.is_initiator {
            return Err(Error::InvalidState(
                "Responder cannot receive IKE_AUTH response".to_string(),
            ));
        }

        if self.state != IkeState::AuthSent {
            return Err(Error::InvalidState(format!(
                "Cannot receive IKE_AUTH response in state {:?}",
                self.state
            )));
        }

        // Validate message ID
        if Some(message_id) != self.expected_response_id {
            return Err(Error::InvalidMessage(format!(
                "Expected message ID {:?}, got {}",
                self.expected_response_id, message_id
            )));
        }

        self.transition(IkeState::Established)?;
        self.expected_response_id = None;
        Ok(())
    }

    /// Handle deletion
    pub fn delete(&mut self) -> Result<()> {
        self.transition(IkeState::Deleting)?;
        self.transition(IkeState::Deleted)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        use IkeState::*;

        // Valid transitions
        assert!(Idle.can_transition_to(InitSent));
        assert!(InitSent.can_transition_to(InitDone));
        assert!(InitDone.can_transition_to(AuthSent));
        assert!(AuthSent.can_transition_to(Established));
        assert!(Established.can_transition_to(Rekeying));
        assert!(Rekeying.can_transition_to(Established));

        // Invalid transitions
        assert!(!Idle.can_transition_to(Established));
        assert!(!InitSent.can_transition_to(AuthSent));
        assert!(!AuthSent.can_transition_to(InitDone));

        // Deletion from any state
        assert!(Idle.can_transition_to(Deleting));
        assert!(Established.can_transition_to(Deleting));
        assert!(Deleting.can_transition_to(Deleted));
    }

    #[test]
    fn test_state_properties() {
        assert!(IkeState::Deleted.is_terminal());
        assert!(!IkeState::Established.is_terminal());

        assert!(IkeState::Established.is_established());
        assert!(!IkeState::InitSent.is_established());

        assert!(IkeState::InitSent.is_waiting());
        assert!(IkeState::AuthSent.is_waiting());
        assert!(!IkeState::Established.is_waiting());
    }

    #[test]
    fn test_initiator_state_machine() {
        let mut sm = IkeStateMachine::new_initiator();

        assert_eq!(sm.state(), IkeState::Idle);
        assert!(sm.is_initiator());

        // Send IKE_SA_INIT
        let msg_id = sm.send_init_request().unwrap();
        assert_eq!(msg_id, 0);
        assert_eq!(sm.state(), IkeState::InitSent);

        // Receive IKE_SA_INIT response
        sm.recv_init_response(0).unwrap();
        assert_eq!(sm.state(), IkeState::InitDone);

        // Send IKE_AUTH
        let msg_id = sm.send_auth_request().unwrap();
        assert_eq!(msg_id, 1);
        assert_eq!(sm.state(), IkeState::AuthSent);

        // Receive IKE_AUTH response
        sm.recv_auth_response(1).unwrap();
        assert_eq!(sm.state(), IkeState::Established);
    }

    #[test]
    fn test_responder_state_machine() {
        let mut sm = IkeStateMachine::new_responder();

        assert_eq!(sm.state(), IkeState::Idle);
        assert!(!sm.is_initiator());

        // Receive IKE_SA_INIT request
        sm.recv_init_request(0).unwrap();
        assert_eq!(sm.state(), IkeState::InitDone);

        // Receive IKE_AUTH request
        sm.recv_auth_request(1).unwrap();
        assert_eq!(sm.state(), IkeState::Established);
    }

    #[test]
    fn test_invalid_message_id() {
        let mut sm = IkeStateMachine::new_initiator();

        sm.send_init_request().unwrap();

        // Wrong message ID in response
        let result = sm.recv_init_response(99);
        assert!(matches!(result, Err(Error::InvalidMessage(_))));
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut sm = IkeStateMachine::new_initiator();

        // Cannot send AUTH before INIT
        let result = sm.send_auth_request();
        assert!(matches!(result, Err(Error::InvalidState(_))));
    }

    #[test]
    fn test_responder_cannot_send_request() {
        let mut sm = IkeStateMachine::new_responder();

        let result = sm.send_init_request();
        assert!(matches!(result, Err(Error::InvalidState(_))));
    }

    #[test]
    fn test_deletion() {
        let mut sm = IkeStateMachine::new_initiator();

        sm.send_init_request().unwrap();
        sm.delete().unwrap();

        assert_eq!(sm.state(), IkeState::Deleted);
        assert!(sm.state().is_terminal());
    }

    #[test]
    fn test_message_id_increment() {
        let mut sm = IkeStateMachine::new_initiator();

        let id1 = sm.send_init_request().unwrap();
        sm.recv_init_response(id1).unwrap();

        let id2 = sm.send_auth_request().unwrap();
        assert_eq!(id2, id1 + 1);
    }
}
