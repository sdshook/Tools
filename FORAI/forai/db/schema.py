"""
Database schemas for FORAI.
"""

EVIDENCE_SCHEMA = """
-- Core evidence table
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    artifact_type TEXT NOT NULL,
    source_file TEXT,
    summary TEXT,
    data JSON,
    hash TEXT,
    confidence REAL DEFAULT 1.0,
    created_at REAL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_evidence_artifact ON evidence(case_id, artifact_type);
"""

GRAPH_SCHEMA = """
-- Graph nodes
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    properties JSON,
    confidence REAL DEFAULT 1.0,
    hash TEXT
);

-- Graph edges
CREATE TABLE IF NOT EXISTS edges (
    edge_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    time_delta REAL DEFAULT 0,
    is_anomalous INTEGER DEFAULT 0,
    anomaly_score REAL DEFAULT 0,
    properties JSON,
    FOREIGN KEY (source_id) REFERENCES nodes(node_id),
    FOREIGN KEY (target_id) REFERENCES nodes(node_id)
);

CREATE INDEX IF NOT EXISTS idx_nodes_case ON nodes(case_id);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(case_id, node_type);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(case_id, edge_type);
"""

CUSTODY_SCHEMA = """
-- Chain of custody log
CREATE TABLE IF NOT EXISTS custody_log (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    file_path TEXT,
    file_hash TEXT,
    user TEXT
);

CREATE INDEX IF NOT EXISTS idx_custody_case ON custody_log(case_id);
"""

TRAJECTORY_SCHEMA = """
-- RL agent trajectories
CREATE TABLE IF NOT EXISTS trajectories (
    trajectory_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL,
    total_reward REAL DEFAULT 0,
    num_steps INTEGER DEFAULT 0
);

-- Individual steps
CREATE TABLE IF NOT EXISTS trajectory_steps (
    id INTEGER PRIMARY KEY,
    trajectory_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    node_id TEXT,
    action TEXT NOT NULL,
    reward REAL DEFAULT 0,
    world_model_score REAL,
    analyst_feedback TEXT,
    timestamp REAL NOT NULL,
    FOREIGN KEY (trajectory_id) REFERENCES trajectories(trajectory_id)
);

CREATE INDEX IF NOT EXISTS idx_traj_case ON trajectories(case_id);
CREATE INDEX IF NOT EXISTS idx_steps_traj ON trajectory_steps(trajectory_id);
"""

WORLD_MODEL_SCHEMA = """
-- State transitions for world model
CREATE TABLE IF NOT EXISTS state_transitions (
    id INTEGER PRIMARY KEY,
    from_state_hash TEXT NOT NULL,
    to_state_hash TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    is_baseline INTEGER DEFAULT 0,
    UNIQUE(from_state_hash, to_state_hash)
);

CREATE INDEX IF NOT EXISTS idx_transitions_from ON state_transitions(from_state_hash);
"""

BHSM_SCHEMA = """
-- BDH memory traces
CREATE TABLE IF NOT EXISTS bdh_traces (
    trace_id TEXT PRIMARY KEY,
    vector BLOB NOT NULL,
    valence REAL DEFAULT 0,
    label TEXT,
    uses INTEGER DEFAULT 0,
    cumulative_reward REAL DEFAULT 0,
    created_at REAL,
    updated_at REAL
);

-- PSI documents
CREATE TABLE IF NOT EXISTS psi_docs (
    doc_id TEXT PRIMARY KEY,
    text TEXT,
    vector BLOB NOT NULL,
    valence REAL DEFAULT 0,
    tags JSON
);

CREATE INDEX IF NOT EXISTS idx_psi_valence ON psi_docs(valence);
"""

LLM_LOG_SCHEMA = """
-- LLM interaction log for provenance
CREATE TABLE IF NOT EXISTS llm_log (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    prompt_hash TEXT NOT NULL,
    response_hash TEXT NOT NULL,
    graph_state_hash TEXT,
    model_name TEXT,
    temperature REAL,
    prompt_text TEXT,
    response_text TEXT
);

CREATE INDEX IF NOT EXISTS idx_llm_case ON llm_log(case_id);
"""

ALL_SCHEMAS = [
    EVIDENCE_SCHEMA,
    GRAPH_SCHEMA,
    CUSTODY_SCHEMA,
    TRAJECTORY_SCHEMA,
    WORLD_MODEL_SCHEMA,
    BHSM_SCHEMA,
    LLM_LOG_SCHEMA,
]
