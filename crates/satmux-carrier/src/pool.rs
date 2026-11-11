//! The carrier pool as a state machine with no I/O and no clock: events and the time go in,
//! actions come out. The shell in `uplink` executes the actions and feeds back what happened.

use std::collections::BTreeMap;
use std::time::Duration;

/// A moment, as the time since the pool's own start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct At(pub Duration);

impl At {
    fn after(self, wait: Duration) -> At {
        At(self.0.saturating_add(wait))
    }

    fn since(self, earlier: At) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

/// One dial and the carrier it may become.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CarrierId(u64);

impl core::fmt::Display for CarrierId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// The pool's whole policy input.
#[derive(Clone, Debug)]
pub struct Rules {
    /// One carrier per port.
    pub ports: Vec<u16>,
    /// Most streams open at once on one carrier, the liveness stream included.
    pub streams: usize,
    pub echo_idle: Duration,
    pub suspect: Duration,
    pub rotate: Duration,
    pub no_carrier_exit: Duration,
}

/// The stream every live carrier holds for its own echoes.
const LIVENESS_STREAMS: usize = 1;

/// Whether a ready carrier owes us an echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Echo {
    Quiet { heard: At },
    Sent { at: At },
}

/// What every connected carrier has, whatever its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Live<S> {
    pub session: S,
    pub streams: usize,
}

/// A carrier's state. A timestamp exists only in the state it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State<S> {
    Dialing { since: At },
    Ready { live: Live<S>, born: At, rtt: Duration, echo: Echo },
    Suspect { live: Live<S>, since: At },
    Draining { live: Live<S>, until: At },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carrier<S> {
    pub id: CarrierId,
    pub port: u16,
    pub state: State<S>,
}

/// Whether any carrier is ready, and since when none has been.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cover {
    Covered,
    Bare { since: At },
    /// Bare for the whole allowance; [`Action::NoCarrier`] has been said.
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<S> {
    DialOk { id: CarrierId, session: S, rtt: Duration },
    DialFailed { id: CarrierId },
    EchoReply { id: CarrierId },
    /// The carrier's connection ended, by either side.
    Died { id: CarrierId },
    /// A stream [`Machine::pick`] counted has ended.
    FlowClosed { id: CarrierId },
    /// Nothing happened but time.
    Tick,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action<S> {
    /// Dial `port` after a wait drawn from zero to `wait_up_to`, and report under `id`.
    Dial { id: CarrierId, port: u16, attempt: u32, wait_up_to: Duration },
    SendEcho { id: CarrierId, session: S },
    /// The pool holds this carrier no longer.
    Close { id: CarrierId, session: S },
    /// No carrier has been ready for the whole allowance.
    NoCarrier,
}

pub struct Machine<S> {
    rules: Rules,
    carriers: Vec<Carrier<S>>,
    /// Per port: dials and unproven carriers lost since an echo last came back on it.
    failures: BTreeMap<u16, u32>,
    cover: Cover,
    minted: u64,
}

impl<S: Clone> Machine<S> {
    /// A pool with nothing dialed, and the dials that start it.
    pub fn new(rules: Rules, now: At) -> (Self, Vec<Action<S>>) {
        let mut machine = Self { rules, carriers: Vec::new(), failures: BTreeMap::new(), cover: Cover::Bare { since: now }, minted: 0 };
        let mut actions = Vec::new();
        machine.settle(now, &mut actions);
        (machine, actions)
    }

    pub fn carriers(&self) -> &[Carrier<S>] {
        &self.carriers
    }

    pub fn cover(&self) -> Cover {
        self.cover
    }

    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    /// The carrier a new stream goes to: ready, with room, the fewest streams, then the
    /// shortest round trip. The stream is counted until [`Event::FlowClosed`].
    pub fn pick(&mut self) -> Option<(CarrierId, S)> {
        let limit = self.rules.streams;
        self.carriers
            .iter_mut()
            .filter_map(|carrier| match &mut carrier.state {
                State::Ready { live, rtt, .. } if live.streams < limit => Some((live.streams, *rtt, carrier.id, live)),
                State::Ready { .. } | State::Dialing { .. } | State::Suspect { .. } | State::Draining { .. } => None,
            })
            .min_by_key(|(streams, rtt, id, _)| (*streams, *rtt, *id))
            .map(|(_, _, id, live)| {
                live.streams += 1;
                (id, live.session.clone())
            })
    }

    /// The next moment a [`Event::Tick`] would change anything.
    pub fn next_deadline(&self) -> Option<At> {
        let rules = &self.rules;
        let carriers = self.carriers.iter().filter_map(|carrier| match &carrier.state {
            State::Dialing { .. } => None,
            State::Ready { born, echo, .. } => {
                let echo_due = match echo {
                    Echo::Quiet { heard } => heard.after(rules.echo_idle),
                    Echo::Sent { at } => at.after(rules.suspect),
                };
                let rotation_due = (!self.dialing(carrier.port)).then(|| born.after(rules.rotate));
                Some(rotation_due.map_or(echo_due, |due| due.min(echo_due)))
            }
            State::Suspect { since, .. } => Some(since.after(rules.suspect)),
            State::Draining { until, .. } => Some(*until),
        });
        let cover = match self.cover {
            Cover::Bare { since } => Some(since.after(rules.no_carrier_exit)),
            Cover::Covered | Cover::Abandoned => None,
        };
        carriers.chain(cover).min()
    }

    pub fn handle(&mut self, now: At, event: Event<S>) -> Vec<Action<S>> {
        let mut actions = Vec::new();
        match event {
            Event::DialOk { id, session, rtt } => self.dial_ok(now, id, session, rtt, &mut actions),
            Event::DialFailed { id } => {
                if let Some(index) = self.carriers.iter().position(|c| c.id == id && matches!(c.state, State::Dialing { .. })) {
                    let carrier = self.carriers.remove(index);
                    self.failed(carrier.port);
                }
            }
            Event::EchoReply { id } => self.echo_reply(now, id),
            Event::Died { id } => {
                if let Some(index) = self.carriers.iter().position(|c| c.id == id) {
                    let carrier = self.carriers.remove(index);
                    match carrier.state {
                        State::Dialing { .. } => self.failed(carrier.port),
                        State::Ready { live, echo: Echo::Sent { .. }, .. } | State::Suspect { live, .. } => {
                            self.failed(carrier.port);
                            actions.push(Action::Close { id, session: live.session });
                        }
                        State::Ready { live, echo: Echo::Quiet { .. }, .. } | State::Draining { live, .. } => {
                            actions.push(Action::Close { id, session: live.session });
                        }
                    }
                }
            }
            Event::FlowClosed { id } => {
                if let Some(index) = self.carriers.iter().position(|c| c.id == id) {
                    let emptied = match &mut self.carriers[index].state {
                        State::Dialing { .. } => false,
                        State::Ready { live, .. } | State::Suspect { live, .. } => {
                            live.streams = live.streams.saturating_sub(1);
                            false
                        }
                        State::Draining { live, .. } => {
                            live.streams = live.streams.saturating_sub(1);
                            live.streams <= LIVENESS_STREAMS
                        }
                    };
                    if emptied {
                        self.close(index, &mut actions);
                    }
                }
            }
            Event::Tick => {}
        }
        self.expire(now, &mut actions);
        self.settle(now, &mut actions);
        actions
    }

    fn dialing(&self, port: u16) -> bool {
        self.carriers.iter().any(|c| c.port == port && matches!(c.state, State::Dialing { .. }))
    }

    fn failed(&mut self, port: u16) {
        let count = self.failures.entry(port).or_default();
        *count = count.saturating_add(1);
    }

    fn close(&mut self, index: usize, actions: &mut Vec<Action<S>>) {
        let carrier = self.carriers.remove(index);
        match carrier.state {
            State::Dialing { .. } => {}
            State::Ready { live, .. } | State::Suspect { live, .. } | State::Draining { live, .. } => {
                actions.push(Action::Close { id: carrier.id, session: live.session });
            }
        }
    }

    fn dial_ok(&mut self, now: At, id: CarrierId, session: S, rtt: Duration, actions: &mut Vec<Action<S>>) {
        let Some(index) = self.carriers.iter().position(|c| c.id == id && matches!(c.state, State::Dialing { .. })) else {
            actions.push(Action::Close { id, session });
            return;
        };
        let port = self.carriers[index].port;
        let drain_until = now.after(self.rules.rotate);
        let mut kept = Vec::with_capacity(self.carriers.len());
        for mut carrier in std::mem::take(&mut self.carriers) {
            if carrier.id == id {
                carrier.state = State::Ready {
                    live: Live { session: session.clone(), streams: LIVENESS_STREAMS },
                    born: now,
                    rtt,
                    echo: Echo::Sent { at: now },
                };
                actions.push(Action::SendEcho { id, session: session.clone() });
                kept.push(carrier);
                continue;
            }
            if carrier.port != port {
                kept.push(carrier);
                continue;
            }
            match carrier.state {
                State::Ready { live, .. } | State::Suspect { live, .. } if live.streams > LIVENESS_STREAMS => {
                    kept.push(Carrier { id: carrier.id, port, state: State::Draining { live, until: drain_until } });
                }
                State::Ready { live, .. } | State::Suspect { live, .. } => {
                    actions.push(Action::Close { id: carrier.id, session: live.session });
                }
                state @ (State::Dialing { .. } | State::Draining { .. }) => kept.push(Carrier { id: carrier.id, port, state }),
            }
        }
        self.carriers = kept;
    }

    fn echo_reply(&mut self, now: At, id: CarrierId) {
        let suspect = self.rules.suspect;
        let Some(carrier) = self.carriers.iter_mut().find(|c| c.id == id) else { return };
        let port = carrier.port;
        let proven = match &mut carrier.state {
            State::Ready { rtt, echo, .. } => {
                if let Echo::Sent { at } = *echo {
                    *rtt = now.since(at);
                }
                *echo = Echo::Quiet { heard: now };
                true
            }
            State::Suspect { live, since } => {
                let rtt = now.since(*since).saturating_add(suspect);
                carrier.state = State::Ready { live: live.clone(), born: now, rtt, echo: Echo::Quiet { heard: now } };
                true
            }
            State::Dialing { .. } | State::Draining { .. } => false,
        };
        if proven {
            self.failures.remove(&port);
        }
    }

    /// Everything that is due by `now` alone.
    fn expire(&mut self, now: At, actions: &mut Vec<Action<S>>) {
        let rules = self.rules.clone();
        let mut index = 0;
        while index < self.carriers.len() {
            /// What the clock does to one carrier.
            enum Due {
                Nothing,
                Echo,
                Suspect,
                Gone { unproven: bool },
            }
            let due = match &self.carriers[index].state {
                State::Dialing { .. } => Due::Nothing,
                State::Ready { echo: Echo::Quiet { heard }, .. } if now >= heard.after(rules.echo_idle) => Due::Echo,
                State::Ready { echo: Echo::Sent { at }, .. } if now >= at.after(rules.suspect) => Due::Suspect,
                State::Ready { .. } => Due::Nothing,
                State::Suspect { since, .. } if now >= since.after(rules.suspect) => Due::Gone { unproven: true },
                State::Suspect { .. } => Due::Nothing,
                State::Draining { until, .. } if now >= *until => Due::Gone { unproven: false },
                State::Draining { .. } => Due::Nothing,
            };
            let carrier = &mut self.carriers[index];
            match due {
                Due::Nothing => {}
                Due::Echo => {
                    if let State::Ready { live, echo, .. } = &mut carrier.state {
                        *echo = Echo::Sent { at: now };
                        actions.push(Action::SendEcho { id: carrier.id, session: live.session.clone() });
                    }
                }
                Due::Suspect => {
                    if let State::Ready { live, .. } = &carrier.state {
                        let live = live.clone();
                        actions.push(Action::SendEcho { id: carrier.id, session: live.session.clone() });
                        carrier.state = State::Suspect { live, since: now };
                    }
                }
                Due::Gone { unproven } => {
                    let port = carrier.port;
                    self.close(index, actions);
                    if unproven {
                        self.failed(port);
                    }
                    continue;
                }
            }
            index += 1;
        }
    }

    /// Makes every port have what it should (a dial in flight unless a ready carrier is young
    /// enough), and brings the cover up to date.
    fn settle(&mut self, now: At, actions: &mut Vec<Action<S>>) {
        for port in self.rules.ports.clone() {
            if self.dialing(port) {
                continue;
            }
            let young = self.carriers.iter().any(|c| match &c.state {
                State::Ready { born, .. } => c.port == port && now < born.after(self.rules.rotate),
                State::Dialing { .. } | State::Suspect { .. } | State::Draining { .. } => false,
            });
            if young {
                continue;
            }
            let id = CarrierId(self.minted);
            self.minted += 1;
            let attempt = self.failures.get(&port).copied().unwrap_or(0);
            self.carriers.push(Carrier { id, port, state: State::Dialing { since: now } });
            actions.push(Action::Dial { id, port, attempt, wait_up_to: self.backoff(attempt) });
        }
        let ready = self.carriers.iter().any(|c| matches!(c.state, State::Ready { .. }));
        self.cover = match (ready, self.cover) {
            (true, _) => Cover::Covered,
            (false, Cover::Covered) => Cover::Bare { since: now },
            (false, Cover::Bare { since }) if now >= since.after(self.rules.no_carrier_exit) => {
                actions.push(Action::NoCarrier);
                Cover::Abandoned
            }
            (false, cover @ (Cover::Bare { .. } | Cover::Abandoned)) => cover,
        };
    }

    /// The longest a dial waits before its `attempt`: nothing the first time, then the suspect
    /// time doubling, never past the echo interval.
    fn backoff(&self, attempt: u32) -> Duration {
        let cap = self.rules.echo_idle.max(self.rules.suspect);
        match attempt.checked_sub(1) {
            None => Duration::ZERO,
            Some(doublings) => self.rules.suspect.saturating_mul(2u32.saturating_pow(doublings)).min(cap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use std::collections::BTreeSet;

    #[derive(Clone, Debug)]
    enum Op {
        /// Time passes and nobody tells the machine.
        Advance(u64),
        Tick,
        /// What the shell does: sleep to the machine's own deadline, then tick.
        Sleep,
        DialOk(Index, u64),
        DialFail(Index),
        Reply(Index),
        Die(Index),
        Pick,
        CloseFlow(Index),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            2 => (0..3000u64).prop_map(Op::Advance),
            1 => Just(Op::Tick),
            3 => Just(Op::Sleep),
            3 => (any::<Index>(), 1..1500u64).prop_map(|(i, rtt)| Op::DialOk(i, rtt)),
            1 => any::<Index>().prop_map(Op::DialFail),
            3 => any::<Index>().prop_map(Op::Reply),
            1 => any::<Index>().prop_map(Op::Die),
            3 => Just(Op::Pick),
            2 => any::<Index>().prop_map(Op::CloseFlow),
        ]
    }

    fn rules() -> impl Strategy<Value = Rules> {
        (proptest::collection::btree_set(1..=u16::MAX, 1..4), 2..6usize, 1..2000u64, 1..2000u64, 1..20_000u64, 1..10_000u64).prop_map(
            |(ports, streams, echo_idle, suspect, rotate, exit)| Rules {
                ports: ports.into_iter().collect(),
                streams,
                echo_idle: Duration::from_millis(echo_idle),
                suspect: Duration::from_millis(suspect),
                rotate: Duration::from_millis(rotate),
                no_carrier_exit: Duration::from_millis(exit),
            },
        )
    }

    /// The reference: what the test knows without asking the machine how it decided.
    struct Model {
        now: At,
        /// Dials asked for and not yet answered.
        dials: Vec<CarrierId>,
        /// Sessions handed in and not yet handed back.
        sessions: BTreeSet<u64>,
        minted: u64,
        /// Flows picked and not yet closed, by carrier.
        flows: Vec<CarrierId>,
        /// Since when no carrier has been ready, and whether that has been said.
        bare: Option<(At, bool)>,
    }

    fn live<S>(state: &State<S>) -> Option<&Live<S>> {
        match state {
            State::Dialing { .. } => None,
            State::Ready { live, .. } | State::Suspect { live, .. } | State::Draining { live, .. } => Some(live),
        }
    }

    impl Model {
        /// Checks one step's actions and the machine's state after it against the reference.
        fn settle(&mut self, machine: &Machine<u64>, actions: Vec<Action<u64>>) -> Result<(), TestCaseError> {
            let rules = machine.rules();
            let mut said = 0;
            for action in actions {
                match action {
                    Action::Dial { id, port, attempt, wait_up_to } => {
                        prop_assert!(rules.ports.contains(&port));
                        prop_assert!(wait_up_to <= rules.echo_idle.max(rules.suspect));
                        prop_assert_eq!(attempt == 0, wait_up_to.is_zero());
                        self.dials.push(id);
                    }
                    Action::SendEcho { id, session } => {
                        let asked = machine.carriers().iter().find(|c| c.id == id).map(|c| &c.state);
                        prop_assert!(
                            matches!(asked, Some(State::Ready { live, .. } | State::Suspect { live, .. }) if live.session == session),
                            "an echo is asked of a carrier that is neither ready nor suspect"
                        );
                    }
                    Action::Close { session, .. } => prop_assert!(self.sessions.remove(&session), "a session is closed twice or was never given"),
                    Action::NoCarrier => said += 1,
                }
            }
            let held: BTreeSet<u64> = machine.carriers().iter().filter_map(|c| live(&c.state)).map(|l| l.session).collect();
            prop_assert_eq!(&held, &self.sessions, "every session given is held or was handed back, never both or neither");
            let dialing: BTreeSet<CarrierId> =
                machine.carriers().iter().filter(|c| matches!(c.state, State::Dialing { .. })).map(|c| c.id).collect();
            prop_assert_eq!(dialing, self.dials.iter().copied().collect::<BTreeSet<_>>(), "every dial in flight was asked for exactly once");
            for port in &rules.ports {
                let on_port = || machine.carriers().iter().filter(|c| c.port == *port);
                let ready: Vec<&At> = on_port().filter_map(|c| if let State::Ready { born, .. } = &c.state { Some(born) } else { None }).collect();
                prop_assert!(ready.len() <= 1, "two ready carriers on one port");
                let dialing = on_port().any(|c| matches!(c.state, State::Dialing { .. }));
                let young = ready.iter().any(|born| self.now < born.after(rules.rotate));
                prop_assert!(dialing || young, "a port has neither a young ready carrier nor a dial in flight");
            }
            for carrier in machine.carriers() {
                if let Some(live) = live(&carrier.state) {
                    prop_assert!(live.streams <= rules.streams);
                }
            }
            let ready = machine.carriers().iter().any(|c| matches!(c.state, State::Ready { .. }));
            if ready {
                self.bare = None;
                prop_assert_eq!(said, 0);
                prop_assert_eq!(machine.cover(), Cover::Covered);
            } else {
                let (since, already) = *self.bare.get_or_insert((self.now, false));
                let due = !already && self.now >= since.after(rules.no_carrier_exit);
                prop_assert_eq!(said, usize::from(due), "no-carrier is said exactly once, when the allowance has passed");
                self.bare = Some((since, already || due));
            }
            Ok(())
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Any history of dials, echoes, deaths, flows and time keeps the pool's promises.
        #[test]
        fn the_pool_keeps_its_promises(rules in rules(), ops in proptest::collection::vec(op(), 1..120)) {
            let start = At(Duration::ZERO);
            let (mut machine, actions) = Machine::<u64>::new(rules, start);
            let mut model = Model { now: start, dials: Vec::new(), sessions: BTreeSet::new(), minted: 0, flows: Vec::new(), bare: Some((start, false)) };
            model.settle(&machine, actions)?;
            for op in ops {
                let event = match op {
                    Op::Advance(ms) => {
                        model.now = model.now.after(Duration::from_millis(ms));
                        continue;
                    }
                    Op::Tick => Event::Tick,
                    Op::Sleep => {
                        let Some(deadline) = machine.next_deadline() else { continue };
                        model.now = model.now.max(deadline);
                        Event::Tick
                    }
                    Op::DialOk(index, rtt) => {
                        if model.dials.is_empty() { continue }
                        let id = model.dials.remove(index.index(model.dials.len()));
                        model.minted += 1;
                        model.sessions.insert(model.minted);
                        Event::DialOk { id, session: model.minted, rtt: Duration::from_millis(rtt) }
                    }
                    Op::DialFail(index) => {
                        if model.dials.is_empty() { continue }
                        Event::DialFailed { id: model.dials.remove(index.index(model.dials.len())) }
                    }
                    Op::Reply(index) | Op::Die(index) => {
                        let connected: Vec<CarrierId> = machine.carriers().iter().filter(|c| live(&c.state).is_some()).map(|c| c.id).collect();
                        if connected.is_empty() { continue }
                        let id = connected[index.index(connected.len())];
                        if let Op::Reply(_) = op { Event::EchoReply { id } } else { Event::Died { id } }
                    }
                    Op::Pick => {
                        let limit = machine.rules().streams;
                        let expected = machine
                            .carriers()
                            .iter()
                            .filter_map(|c| match &c.state {
                                State::Ready { live, rtt, .. } if live.streams < limit => Some((live.streams, *rtt, c.id, live.session)),
                                _ => None,
                            })
                            .min()
                            .map(|(streams, _, id, session)| (id, session, streams));
                        let picked = machine.pick();
                        prop_assert_eq!(picked, expected.map(|(id, session, _)| (id, session)), "a flow goes to the least-loaded ready carrier, or nowhere");
                        if let Some((id, _, before)) = expected {
                            let after = machine.carriers().iter().find(|c| c.id == id).and_then(|c| live(&c.state)).map(|l| l.streams);
                            prop_assert_eq!(after, Some(before + 1));
                            model.flows.push(id);
                        }
                        continue;
                    }
                    Op::CloseFlow(index) => {
                        if model.flows.is_empty() { continue }
                        Event::FlowClosed { id: model.flows.remove(index.index(model.flows.len())) }
                    }
                };
                let actions = machine.handle(model.now, event);
                model.settle(&machine, actions)?;
                prop_assert!(machine.next_deadline().is_none_or(|deadline| deadline > model.now), "the machine asks to be woken in the past");
            }
        }

        /// A carrier whose echoes all come back in time is never suspected, and one whose
        /// echoes never come back is gone after two suspect times and takes no flow meanwhile.
        #[test]
        fn echoes_decide_suspicion(rules in rules(), answers in any::<bool>(), rounds in 1..20usize) {
            let mut rules = rules;
            rules.ports.truncate(1);
            rules.rotate = Duration::MAX;
            let start = At(Duration::ZERO);
            let (mut machine, actions) = Machine::<u64>::new(rules.clone(), start);
            let Some(Action::Dial { id, .. }) = actions.into_iter().next() else { panic!("a new pool dials") };
            machine.handle(start, Event::DialOk { id, session: 0, rtt: Duration::ZERO });
            let mut now = start;
            for _ in 0..rounds {
                if answers {
                    machine.handle(now, Event::EchoReply { id });
                    let state = machine.carriers().iter().find(|c| c.id == id).map(|c| &c.state);
                    prop_assert!(matches!(state, Some(State::Ready { .. })), "an answered carrier stays ready");
                }
                let Some(deadline) = machine.next_deadline() else { break };
                now = deadline;
                machine.handle(now, Event::Tick);
            }
            let state = machine.carriers().iter().find(|c| c.id == id).map(|c| &c.state);
            if answers {
                prop_assert!(matches!(state, Some(State::Ready { .. })), "an answered carrier stays ready");
            } else {
                let silent = now.since(start);
                let expected_gone = silent >= rules.suspect.saturating_add(rules.suspect);
                prop_assert_eq!(state.is_none(), expected_gone);
                if silent >= rules.suspect {
                    prop_assert!(!matches!(state, Some(State::Ready { .. })), "a silent carrier is still ready");
                    prop_assert_eq!(machine.pick(), None);
                }
            }
        }
    }
}
