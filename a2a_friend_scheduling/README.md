# A2A Friend Scheduling Demo

A multi-agent application demonstrating how to orchestrate conversations between different agents to schedule a pickleball game. The transport layer uses [MoQT (Media over QUIC Transport)](https://datatracker.ietf.org/doc/draft-nandakumar-a2a-moqt-transport/) instead of HTTP, giving agents built-in support for priority, cancellation, and relay-based discovery.

This application contains four agents:
*   **Host Agent**: Orchestrates the scheduling task and runs the ADK web UI.
*   **Kaitlynn Agent**: Represents Kaitlynn's calendar (LangGraph).
*   **Nate Agent**: Represents Nate's calendar (CrewAI).
*   **Karley Agent**: Represents Karley's calendar (Google ADK).

---

## Setup

### Prerequisites

1. **uv** — Python package manager: [installation guide](https://docs.astral.sh/uv/getting-started/installation/)
2. **Python ≥ 3.10** (Kaitlynn agent requires ≥ 3.12)
3. **.env** — copy the template and fill in your key:

```bash
cp .env.example .env
# then edit .env and set GOOGLE_API_KEY
```

---

## Transport Modes

The agents support two transport modes, controlled by a single env var.

### Mode A — Direct (no relay, default)

Each friend agent listens on its own QUIC port. The host connects to each by
its hardcoded address. No relay process is needed.

| Agent | MOQT Port |
|---|---|
| Karley | 20002 |
| Nate | 20003 |
| Kaitlynn | 20004 |

Leave `MOQT_RELAY_URL` **unset** (or commented out) in `.env`.

### Mode B — Relay (recommended)

A single MoQ Lite Relay runs on port 20000. All friend agents connect **to
the relay** (no open ports of their own). The host discovers them
automatically via `SUBSCRIBE_NAMESPACE` — no hardcoded addresses needed.

Add this line to `.env`:

```
MOQT_RELAY_URL=moqt://localhost:20000
```

---

## Run the Agents

Open **5 terminal windows** (relay mode) or **4 terminal windows** (direct mode).
Run each command from inside the `a2a_friend_scheduling/` directory.

### Terminal 0 — Relay *(relay mode only)*

```bash
python -m moqt_transport --host localhost --port 20000
```

### Terminal 1 — Kaitlynn Agent

```bash
cd kaitlynn_agent_langgraph
uv venv && source .venv/bin/activate
uv run --active app/__main__.py
```

### Terminal 2 — Nate Agent

```bash
cd nate_agent_crewai
uv venv && source .venv/bin/activate
uv run --active .
```

### Terminal 3 — Karley Agent

```bash
cd karley_agent_adk
uv venv && source .venv/bin/activate
uv run --active .
```

### Terminal 4 — Host Agent (ADK web UI)

```bash
cd host_agent_adk
uv venv && source .venv/bin/activate
uv run --active adk web
```

The ADK web UI will be available at **http://localhost:8000**.

> **Relay mode startup order matters**: start the relay first, then the
> friend agents, then the host. The host runs discovery at startup so all
> friends must be connected to the relay before it initialises.

---

## Interact with the Host Agent

Open [http://localhost:8000](http://localhost:8000) in your browser. You can
ask the host agent things like:

- *"Schedule a pickleball game with Karley and Nate this weekend"*
- *"Who is free on Saturday afternoon?"*
- *"Book a court for everyone who is available on Friday at 5pm"*

In **relay mode**, the host discovers friends automatically — you do not need
to restart it when agents join or leave the relay.

---

## Quick Sanity Check (no API key needed)

Verify the relay and inter-agent discovery work end-to-end without real LLM
calls:

```bash
# Runs relay + two mock agents + a host client and prints discovery results
python demo_relay.py
```

---

## References
- https://github.com/google/a2a-python
- https://datatracker.ietf.org/doc/draft-nandakumar-a2a-moqt-transport/
- https://codelabs.developers.google.com/intro-a2a-purchasing-concierge#1
